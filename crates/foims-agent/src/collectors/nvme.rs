//! nvme 采集器：NVMe 控制器与命名空间指标。
//!
//! 对齐 node_exporter `nvme_linux.go`（默认启用）与 procfs sysfs NVMeClass
//! （v0.23.0）：遍历 /sys/class/nvme/，读取控制器属性（firmware_rev/model/
//! serial/state/cntlid 全部必需）与命名空间目录（目录名匹配
//! ^nvme\d+(c\d+)?n\d+$，ID 优先取内核 nsid 文件、否则取目录名编号），
//! 输出子系统 nvme 的 6 个指标族（全 Gauge）：
//! - `node_nvme_info`（值恒 1，标签 device/firmware_revision/model/serial/
//!   state/cntlid）；
//! - `node_nvme_namespace_info`（值恒 1，标签 device/nsid/ana_state，
//!   ana_state 缺失默认 unknown）；
//! - `node_nvme_namespace_capacity_bytes` / `_size_bytes`（均 = size 扇区
//!   数 × 512，块层固定 512 字节扇区）；
//! - `node_nvme_namespace_used_bytes`（nuse × 逻辑块大小；nuse 读取需内核
//!   查询控制器）；
//! - `node_nvme_namespace_logical_block_size_bytes`
//!   （queue/logical_block_size）。
//!
//! 偏离点：
//! - 未移植 --collector.nvme.namespace-usage 开关（对齐其默认 true：恒定
//!   采集 nuse）；
//! - nuse 缺失静默跳过（内核 <6.8 不暴露）；读取/解析失败记录 warn 日志并
//!   跳过该命名空间的 used 指标（对齐 Go 默认行为）；
//! - 设备按名字典序输出（Go map 遍历无序）；
//! - class/nvme 目录缺失时返回空指标族（Go 侧为 ErrNoData）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// NVMe 设备目录（相对 sys_path）
const NVME_DIR: &str = "class/nvme";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;
/// 块层固定扇区大小（对齐 procfs blockSectorSize）
const SECTOR_SIZE: u64 = 512;

pub struct NvmeCollector {
    sys_path: PathBuf,
}

impl NvmeCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for NvmeCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// NVMe 命名空间（对应 procfs NVMeNamespace，仅保留输出字段）
#[derive(Debug)]
struct NvmeNamespace {
    /// 命名空间块设备目录名（如 nvme0n1 / nvme0c1n1）
    name: String,
    /// 命名空间 ID（nsid 文件优先，否则目录名编号）
    id: String,
    /// size 文件值（512 字节扇区总数）
    size_blocks: u64,
    /// queue/logical_block_size 文件值
    logical_block_size: u64,
    /// ana_state 文件值（缺失默认 unknown）
    ana_state: String,
    /// nuse × 逻辑块大小（nuse 缺失或读取失败为 None）
    used_bytes: Option<u64>,
}

/// NVMe 控制器（对应 procfs NVMeDevice，仅保留输出字段）
#[derive(Debug)]
struct NvmeDevice {
    name: String,
    firmware_revision: String,
    model: String,
    serial: String,
    state: String,
    controller_id: String,
    /// 已按目录名排序
    namespaces: Vec<NvmeNamespace>,
}

/// 匹配命名空间目录名（对齐 procfs nvmeNamespacePattern
/// `^nvme\d+(?:c\d+)?n(\d+)$`），返回目录名编号
fn namespace_dir_id(name: &str) -> Option<&str> {
    let mut rest = name.strip_prefix("nvme")?;
    // 控制器编号段（≥1 位数字）
    let digits_end = rest.find(|c: char| !c.is_ascii_digit())?;
    if digits_end == 0 {
        return None;
    }
    rest = &rest[digits_end..];
    // 可选的 c<num> 段（原生多路径共享命名空间的隐藏路径设备）
    if let Some(after_c) = rest.strip_prefix('c') {
        let c_end = after_c.find(|c: char| !c.is_ascii_digit())?;
        if c_end == 0 {
            return None;
        }
        rest = &after_c[c_end..];
    }
    // n<编号> 段延伸到串尾
    let id = rest.strip_prefix('n')?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(id)
}

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: NVME_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 解析单个 NVMe 控制器目录（对齐 procfs parseNVMeDevice）
fn parse_nvme_device(sys_path: &Path, name: &str) -> Result<NvmeDevice, CollectorError> {
    let device_path = sys_path.join(NVME_DIR).join(name);

    // 控制器属性 5 个文件全部必需（对齐 Go 读取失败即报错）
    let mut firmware_revision = String::new();
    let mut model = String::new();
    let mut serial = String::new();
    let mut state = String::new();
    let mut controller_id = String::new();
    for (file, slot) in [
        ("firmware_rev", &mut firmware_revision),
        ("model", &mut model),
        ("serial", &mut serial),
        ("state", &mut state),
        ("cntlid", &mut controller_id),
    ] {
        *slot = sys_read_file(&device_path.join(file))?;
    }

    let mut namespaces = Vec::new();
    for entry in std::fs::read_dir(&device_path)? {
        let entry = entry?;
        let Some(dir_name) = entry.file_name().into_string().ok() else {
            continue;
        };
        // 正则不匹配的条目（queue 等子目录）跳过
        let Some(dir_id) = namespace_dir_id(&dir_name) else {
            continue;
        };
        let namespace_path = device_path.join(&dir_name);

        // 目录名编号仅按惯例与 NSID 一致，内核暴露 nsid 文件时优先取之
        let mut id = dir_id.to_string();
        if let Ok(value) = sys_read_file(&namespace_path.join("nsid")) {
            id = value;
        }

        let mut namespace = NvmeNamespace {
            name: dir_name,
            id,
            size_blocks: 0,
            logical_block_size: 0,
            ana_state: "unknown".to_string(),
            used_bytes: None,
        };
        for (file, required) in [
            ("size", true),
            ("queue/logical_block_size", true),
            ("ana_state", false),
        ] {
            let value = match sys_read_file(&namespace_path.join(file)) {
                Ok(value) => value,
                // ana_state 的任何读取错误均静默跳过（保持 unknown，对齐 Go）
                Err(_) if !required => continue,
                Err(error) => return Err(error),
            };
            match file {
                // 解析失败静默置 0（对齐 Go ParseUint 错误忽略）
                "size" => namespace.size_blocks = value.parse::<u64>().unwrap_or(0),
                "queue/logical_block_size" => {
                    namespace.logical_block_size = value.parse::<u64>().unwrap_or(0);
                }
                _ => namespace.ana_state = value,
            }
        }

        // nuse 需内核查询控制器，读取按需进行且可能失败（如控制器非 live
        // 时 EIO）：失败仅告警并跳过 used 指标，不影响其余采集
        let nuse_path = namespace_path.join("nuse");
        namespace.used_bytes = match sys_read_file(&nuse_path) {
            Ok(value) => match value.parse::<u64>() {
                Ok(blocks) => Some(blocks.wrapping_mul(namespace.logical_block_size)),
                Err(error) => {
                    tracing::warn!(
                        device = %name,
                        namespace = %namespace.name,
                        error = %error,
                        "NVMe 命名空间 nuse 值非法，跳过 used 指标"
                    );
                    None
                }
            },
            // 内核 <6.8 不暴露 nuse，静默跳过（对齐 Go Debug 级日志）
            Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!(
                    device = %name,
                    namespace = %namespace.name,
                    error = %error,
                    "NVMe 命名空间 nuse 读取失败，跳过 used 指标"
                );
                None
            }
        };

        namespaces.push(namespace);
    }
    // 对齐 Go os.ReadDir 的目录名排序
    namespaces.sort_by_key(|namespace| namespace.name.clone());

    Ok(NvmeDevice {
        name: name.to_string(),
        firmware_revision,
        model,
        serial,
        state,
        controller_id,
        namespaces,
    })
}

impl Collector for NvmeCollector {
    fn name(&self) -> &'static str {
        "nvme"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let nvme_dir = self.sys_path.join(NVME_DIR);
        let mut device_names: Vec<String> = Vec::new();
        match std::fs::read_dir(&nvme_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if let Ok(name) = entry.file_name().into_string() {
                        device_names.push(name);
                    }
                }
            }
            // class/nvme 目录缺失（无 NVMe 设备）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        }
        // 设备按名字典序输出（Go map 遍历无序，仅为输出稳定性）
        device_names.sort();

        let mut devices = Vec::with_capacity(device_names.len());
        for name in device_names {
            devices.push(parse_nvme_device(&self.sys_path, &name)?);
        }

        // 预建 6 个指标族（顺序对齐 Go Update 推送序）
        let mut info = MetricFamily::new(
            "node_nvme_info",
            "Non-numeric data from /sys/class/nvme/<device>, value is always 1.",
            MetricType::Gauge,
        );
        let mut namespace_info = MetricFamily::new(
            "node_nvme_namespace_info",
            "Information about NVMe namespaces. Value is always 1",
            MetricType::Gauge,
        );
        let mut namespace_capacity_bytes = MetricFamily::new(
            "node_nvme_namespace_capacity_bytes",
            "Capacity of the NVMe namespace in bytes.",
            MetricType::Gauge,
        );
        let mut namespace_size_bytes = MetricFamily::new(
            "node_nvme_namespace_size_bytes",
            "Size of the NVMe namespace in bytes. Available in /sys/class/nvme/<device>/<namespace>/size",
            MetricType::Gauge,
        );
        let mut namespace_used_bytes = MetricFamily::new(
            "node_nvme_namespace_used_bytes",
            "Used space of the NVMe namespace in bytes. Available in /sys/class/nvme/<device>/<namespace>/nuse",
            MetricType::Gauge,
        );
        let mut namespace_logical_block_size_bytes = MetricFamily::new(
            "node_nvme_namespace_logical_block_size_bytes",
            "Logical block size of the NVMe namespace in bytes. Usually 4Kb. Available in /sys/class/nvme/<device>/<namespace>/queue/logical_block_size",
            MetricType::Gauge,
        );

        for device in devices {
            info.push_labeled(
                vec![
                    ("device".to_string(), device.name.clone()),
                    ("firmware_revision".to_string(), device.firmware_revision),
                    ("model".to_string(), device.model),
                    ("serial".to_string(), device.serial),
                    ("state".to_string(), device.state),
                    ("cntlid".to_string(), device.controller_id),
                ],
                1.0,
            );

            for namespace in device.namespaces {
                let device_labels = vec![
                    ("device".to_string(), device.name.clone()),
                    ("nsid".to_string(), namespace.id.clone()),
                ];
                let mut info_labels = device_labels.clone();
                info_labels.push(("ana_state".to_string(), namespace.ana_state.clone()));
                namespace_info.push_labeled(info_labels, 1.0);

                // 块层固定以 512 字节扇区上报 size（对齐 Go：SizeBytes =
                // CapacityBytes = SizeBlocks × 512）
                let size_bytes = namespace.size_blocks.wrapping_mul(SECTOR_SIZE);
                namespace_capacity_bytes.push_labeled(device_labels.clone(), size_bytes as f64);
                namespace_size_bytes.push_labeled(device_labels.clone(), size_bytes as f64);
                if let Some(used_bytes) = namespace.used_bytes {
                    namespace_used_bytes.push_labeled(device_labels.clone(), used_bytes as f64);
                }
                namespace_logical_block_size_bytes
                    .push_labeled(device_labels, namespace.logical_block_size as f64);
            }
        }

        Ok(vec![
            info,
            namespace_info,
            namespace_capacity_bytes,
            namespace_size_bytes,
            namespace_used_bytes,
            namespace_logical_block_size_bytes,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 按完整标签集定位样本值
    fn value_of(family: &MetricFamily, labels: &[(&str, &str)]) -> f64 {
        family
            .samples
            .iter()
            .find(|sample| {
                sample.labels.len() == labels.len()
                    && sample
                        .labels
                        .iter()
                        .all(|(key, value)| labels.iter().any(|(k, v)| k == key && v == value))
            })
            .unwrap_or_else(|| panic!("缺少样本 {labels:?}"))
            .value
    }

    /// 按指标名定位族
    fn family_of<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|family| family.name == name)
            .unwrap_or_else(|| panic!("缺少指标族 {name}"))
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    /// 按 fixture 推导的黄金期望（上游无 Go 测试；数值来源：size=
    /// 3906250000×512=2e12，nuse=488281250×4096=2e12，逻辑块 4096，
    /// ana_state=optimized，nsid 取目录名编号 1，对齐 e2e-output.txt 的
    /// nvme 段）
    #[test]
    fn test_collect_matches_fixture() {
        let families = NvmeCollector::with_root(fixture_root())
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 6);

        // info：6 个标签齐全
        let info = family_of(&families, "node_nvme_info");
        assert_eq!(info.samples.len(), 1);
        assert_eq!(info.samples[0].value, 1.0);
        let get_label = |key: &str| -> String {
            info.samples[0]
                .labels
                .iter()
                .find(|(k, _)| k == key)
                .unwrap_or_else(|| panic!("缺少标签 {key}"))
                .1
                .clone()
        };
        assert_eq!(get_label("device"), "nvme0");
        assert_eq!(get_label("firmware_revision"), "1B2QEXP7");
        assert_eq!(get_label("model"), "Samsung SSD 970 PRO 512GB");
        assert_eq!(get_label("serial"), "S680HF8N190894I");
        assert_eq!(get_label("state"), "live");
        assert_eq!(get_label("cntlid"), "1997");

        // 命名空间指标（nsid=1）
        assert_eq!(
            value_of(
                family_of(&families, "node_nvme_namespace_info"),
                &[
                    ("device", "nvme0"),
                    ("nsid", "1"),
                    ("ana_state", "optimized")
                ]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_nvme_namespace_capacity_bytes"),
                &[("device", "nvme0"), ("nsid", "1")]
            ),
            2_000_000_000_000.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_nvme_namespace_size_bytes"),
                &[("device", "nvme0"), ("nsid", "1")]
            ),
            2_000_000_000_000.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_nvme_namespace_used_bytes"),
                &[("device", "nvme0"), ("nsid", "1")]
            ),
            2_000_000_000_000.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_nvme_namespace_logical_block_size_bytes"),
                &[("device", "nvme0"), ("nsid", "1")]
            ),
            4096.0
        );
    }

    /// 命名空间目录名匹配对齐 ^nvme\d+(c\d+)?n(\d+)$
    #[test]
    fn test_namespace_dir_id() {
        assert_eq!(namespace_dir_id("nvme0n1"), Some("1"));
        assert_eq!(namespace_dir_id("nvme12c3n45"), Some("45"));
        assert_eq!(namespace_dir_id("nvme0"), None);
        assert_eq!(namespace_dir_id("nvme0n"), None);
        assert_eq!(namespace_dir_id("nvmecn1"), None);
        assert_eq!(namespace_dir_id("nvme0n1x"), None);
        assert_eq!(namespace_dir_id("nvme0c1n2x"), None);
    }

    /// class/nvme 目录缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_nvme_dir_yields_empty() {
        let families = NvmeCollector::with_root(PathBuf::from("/nonexistent-foims-test"))
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }
}
