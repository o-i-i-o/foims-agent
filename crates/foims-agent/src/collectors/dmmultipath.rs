//! dmmultipath 采集器：DM-multipath 设备指标。
//!
//! 对齐 node_exporter `dmmultipath_linux.go`（默认启用）与 procfs
//! blockdevice.DMMultipathDevices（v0.23.0）：遍历 /sys/block/dm-*，仅处理
//! dm/uuid 以 "mpath-" 开头的设备（dm/uuid 缺失视为非 device-mapper 设备，
//! 跳过），输出子系统 dmmultipath 的 7 个指标族（全 Gauge）：
//! - `node_dmmultipath_device_info`（值恒 1，标签 device/sysfs_name/uuid）；
//! - `node_dmmultipath_device_active`（dm/suspended=0 时为 1，否则 0）；
//! - `node_dmmultipath_device_size_bytes`（size 扇区数 × 512）；
//! - `node_dmmultipath_path_state`（值恒 1，标签 device/path/state）；
//! - `node_dmmultipath_device_paths` / `_paths_active` / `_paths_failed`
//!   （路径总数 / running|live 活跃路径数 / 其余状态路径数）。
//!
//! 偏离点：
//! - 断链路径（slave 符号链接悬空导致 /sys/block/<slave>/device/state 不
//!   存在）按"无 state"处理：记为 failed 路径、path_state 标签 state=""
//!   （Go 侧传播错误导致整轮采集失败）；
//! - /sys/block 目录缺失或不可读时返回空指标族（Go 侧为 ErrNoData）；
//! - 未沿用 Go blockdevice.NewFS 的 proc/sys 双根签名（本采集器仅读取
//!   sys/block，故只注入 sys 根）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// block 设备目录（相对 sys_path）
const BLOCK_DIR: &str = "block";
/// dm 元数据子目录
const DM_DIR: &str = "dm";
/// 底层路径设备子目录
const SLAVES_DIR: &str = "slaves";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;
/// 块层固定扇区大小（对齐 procfs SectorSize）
const SECTOR_SIZE: u64 = 512;

pub struct DmMultipathCollector {
    sys_path: PathBuf,
}

impl DmMultipathCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for DmMultipathCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// DM-multipath 路径设备（对应 procfs DMMultipathPath）
#[derive(Debug)]
struct DmPath {
    device: String,
    state: String,
}

/// DM-multipath 设备（对应 procfs DMMultipathDevice）
#[derive(Debug)]
struct DmDevice {
    name: String,
    sysfs_name: String,
    uuid: String,
    suspended: bool,
    size_bytes: u64,
    paths: Vec<DmPath>,
}

/// 判定路径状态是否为活跃（SCSI running / NVMe live，对齐 Go isPathActive）
fn is_path_active(state: &str) -> bool {
    state == "running" || state == "live"
}

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: BLOCK_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 读取无符号整数文件（对齐 procfs ReadUintFromFile：全量读取 + 去空白 +
/// 10 进制解析）
fn read_uint_file(path: &Path) -> Result<u64, CollectorError> {
    let bytes = std::fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes);
    let value = content.trim();
    value.parse::<u64>().map_err(|error| CollectorError::Parse {
        file: BLOCK_DIR,
        reason: format!("{} 值非法: {error}", path.display()),
    })
}

/// 解析单个 dm-* 设备目录（对齐 procfs DMMultipathDevices 单设备流程；
/// 非 mpath 设备返回 None）
fn parse_dm_device(sys_path: &Path, dm_path: &Path) -> Result<Option<DmDevice>, CollectorError> {
    let dm_dir = dm_path.join(DM_DIR);
    // dm/uuid 缺失 → 非 device-mapper 设备，跳过（对齐 Go os.IsNotExist）
    let uuid = match sys_read_file(&dm_dir.join("uuid")) {
        Ok(uuid) => uuid,
        Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if !uuid.starts_with("mpath-") {
        return Ok(None);
    }
    let sysfs_name = dm_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let name = sys_read_file(&dm_dir.join("name"))?;
    let suspended = read_uint_file(&dm_dir.join("suspended"))? == 1;
    let size_bytes = read_uint_file(&dm_path.join("size"))?.wrapping_mul(SECTOR_SIZE);

    // slaves/ 目录缺失 → 无路径设备（对齐 Go os.IsNotExist → 空切片）
    let slaves_dir = dm_path.join(SLAVES_DIR);
    let mut slave_names: Vec<String> = match std::fs::read_dir(&slaves_dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    // 对齐 Go os.ReadDir 的名字排序（Rust read_dir 无序）
    slave_names.sort();

    let mut paths = Vec::with_capacity(slave_names.len());
    for slave in slave_names {
        // 路径状态取自 /sys/block/<slave>/device/state（与 dm 条目自身的
        // 符号链接无关，仅使用 slave 名）
        let state_path = sys_path
            .join(BLOCK_DIR)
            .join(&slave)
            .join("device")
            .join("state");
        let state = match sys_read_file(&state_path) {
            Ok(state) => state,
            // 断链 slave（符号链接悬空）按"无 state"处理，记为 failed 路径
            Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(error) => return Err(error),
        };
        paths.push(DmPath {
            device: slave,
            state,
        });
    }

    Ok(Some(DmDevice {
        name,
        sysfs_name,
        uuid,
        suspended,
        size_bytes,
        paths,
    }))
}

impl Collector for DmMultipathCollector {
    fn name(&self) -> &'static str {
        "dmmultipath"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let block_dir = self.sys_path.join(BLOCK_DIR);
        let mut dm_paths: Vec<PathBuf> = match std::fs::read_dir(&block_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("dm-"))
                })
                .collect(),
            // /sys/block 缺失或不可读 → 空指标族（Go 侧为 ErrNoData）
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        // 对齐 Go os.ReadDir 的名字排序
        dm_paths.sort();

        let mut devices = Vec::new();
        for dm_path in dm_paths {
            if let Some(device) = parse_dm_device(&self.sys_path, &dm_path)? {
                devices.push(device);
            }
        }

        // 预建 7 个指标族（顺序对齐 Go Update 推送序）
        let mut device_info = MetricFamily::new(
            "node_dmmultipath_device_info",
            "Non-numeric information about a DM-multipath device.",
            MetricType::Gauge,
        );
        let mut device_active = MetricFamily::new(
            "node_dmmultipath_device_active",
            "Whether the multipath device-mapper device is active (1) or suspended (0).",
            MetricType::Gauge,
        );
        let mut device_size_bytes = MetricFamily::new(
            "node_dmmultipath_device_size_bytes",
            "Size of the multipath device in bytes, read from /sys/block/<dm>/size.",
            MetricType::Gauge,
        );
        let mut path_state = MetricFamily::new(
            "node_dmmultipath_path_state",
            "Reports the underlying device state for a multipath path, as read from /sys/block/<dev>/device/state.",
            MetricType::Gauge,
        );
        let mut device_paths = MetricFamily::new(
            "node_dmmultipath_device_paths",
            "Number of paths for a multipath device.",
            MetricType::Gauge,
        );
        let mut device_paths_active = MetricFamily::new(
            "node_dmmultipath_device_paths_active",
            "Number of paths in active state (SCSI running or NVMe live) for a multipath device.",
            MetricType::Gauge,
        );
        let mut device_paths_failed = MetricFamily::new(
            "node_dmmultipath_device_paths_failed",
            "Number of paths not in active state for a multipath device.",
            MetricType::Gauge,
        );

        for device in devices {
            let base = vec![
                ("device".to_string(), device.name.clone()),
                ("sysfs_name".to_string(), device.sysfs_name),
            ];
            let mut info_labels = base.clone();
            info_labels.push(("uuid".to_string(), device.uuid));
            device_info.push_labeled(info_labels, 1.0);
            device_active.push_labeled(base.clone(), if device.suspended { 0.0 } else { 1.0 });
            device_size_bytes.push_labeled(base.clone(), device.size_bytes as f64);

            let paths_count = device.paths.len();
            let mut active_paths = 0.0;
            let mut failed_paths = 0.0;
            for path in &device.paths {
                if is_path_active(&path.state) {
                    active_paths += 1.0;
                } else {
                    failed_paths += 1.0;
                }
                path_state.push_labeled(
                    vec![
                        ("device".to_string(), device.name.clone()),
                        ("path".to_string(), path.device.clone()),
                        ("state".to_string(), path.state.clone()),
                    ],
                    1.0,
                );
            }
            device_paths.push_labeled(base.clone(), paths_count as f64);
            device_paths_active.push_labeled(base.clone(), active_paths);
            device_paths_failed.push_labeled(base, failed_paths);
        }

        Ok(vec![
            device_info,
            device_active,
            device_size_bytes,
            path_state,
            device_paths,
            device_paths_active,
            device_paths_failed,
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

    fn fixture_root(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// 对齐 Go TestDMMultipathMetrics 的 e2o 黄金期望
    #[test]
    fn test_collect_matches_fixture() {
        let families = DmMultipathCollector::with_root(fixture_root("sys"))
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 7);

        // device_info：uuid 标签
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_info"),
                &[
                    ("device", "mpathA"),
                    ("sysfs_name", "dm-5"),
                    ("uuid", "mpath-3600508b1001c1234567890abcdef1234"),
                ]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_info"),
                &[
                    ("device", "mpathB"),
                    ("sysfs_name", "dm-6"),
                    ("uuid", "mpath-3600508b1001cabcdef4567890123456"),
                ]
            ),
            1.0
        );

        // device_active：suspended=0 → 1
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_active"),
                &[("device", "mpathA"), ("sysfs_name", "dm-5")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_active"),
                &[("device", "mpathB"), ("sysfs_name", "dm-6")]
            ),
            1.0
        );

        // device_size_bytes：扇区数 × 512
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_size_bytes"),
                &[("device", "mpathA"), ("sysfs_name", "dm-5")]
            ),
            53_687_091_200.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_size_bytes"),
                &[("device", "mpathB"), ("sysfs_name", "dm-6")]
            ),
            107_374_182_400.0
        );

        // path_state：6 条路径（含 offline）
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_path_state"),
                &[("device", "mpathA"), ("path", "sdi"), ("state", "running")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_path_state"),
                &[("device", "mpathA"), ("path", "sdl"), ("state", "offline")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_path_state"),
                &[("device", "mpathB"), ("path", "sdn"), ("state", "running")]
            ),
            1.0
        );
        assert_eq!(
            family_of(&families, "node_dmmultipath_path_state")
                .samples
                .len(),
            6
        );

        // 路径计数
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths"),
                &[("device", "mpathA"), ("sysfs_name", "dm-5")]
            ),
            4.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_active"),
                &[("device", "mpathA"), ("sysfs_name", "dm-5")]
            ),
            3.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_failed"),
                &[("device", "mpathA"), ("sysfs_name", "dm-5")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths"),
                &[("device", "mpathB"), ("sysfs_name", "dm-6")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_active"),
                &[("device", "mpathB"), ("sysfs_name", "dm-6")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_failed"),
                &[("device", "mpathB"), ("sysfs_name", "dm-6")]
            ),
            0.0
        );
    }

    /// 断链 slave（悬空符号链接）按"无 state"处理：记为 failed 路径，
    /// path_state 标签 state 为空串
    #[test]
    fn test_broken_slave_symlink_treated_as_no_state() {
        let families = DmMultipathCollector::with_root(fixture_root("sys-dm-broken"))
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));

        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_info"),
                &[
                    ("device", "mpathX"),
                    ("sysfs_name", "dm-8"),
                    ("uuid", "mpath-3600508b1001cdeadbeefdeadbeef0001"),
                ]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_path_state"),
                &[("device", "mpathX"), ("path", "sdz"), ("state", "")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths"),
                &[("device", "mpathX"), ("sysfs_name", "dm-8")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_active"),
                &[("device", "mpathX"), ("sysfs_name", "dm-8")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_dmmultipath_device_paths_failed"),
                &[("device", "mpathX"), ("sysfs_name", "dm-8")]
            ),
            1.0
        );
    }

    /// /sys/block 目录缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_block_dir_yields_empty() {
        let families = DmMultipathCollector::with_root(PathBuf::from("/nonexistent-foims-test"))
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    /// 对齐 Go TestIsPathActive 的 8 组用例
    #[test]
    fn test_is_path_active() {
        assert!(is_path_active("running"));
        assert!(is_path_active("live"));
        assert!(!is_path_active("offline"));
        assert!(!is_path_active("blocked"));
        assert!(!is_path_active("transport-offline"));
        assert!(!is_path_active("dead"));
        assert!(!is_path_active("unknown"));
        assert!(!is_path_active(""));
    }
}
