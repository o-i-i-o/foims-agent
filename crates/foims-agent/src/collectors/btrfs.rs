//! btrfs 采集器：Btrfs 文件系统分配与提交统计。
//!
//! 对齐 node_exporter `btrfs_linux.go`（默认启用）+ procfs btrfs 包
//! Stats（glob /sys/fs/btrfs/*-*）：每个文件系统输出 11 个指标族
//! （前缀 node_btrfs_，基础标签 uuid）：info（额外标签 label）、
//! global_rsv_size_bytes、commits_total、last_commit_seconds、
//! max_commit_seconds、commit_seconds_total、reserved_bytes（标签
//! block_group_type）、used_bytes/size_bytes/allocation_ratio（标签
//! block_group_type+mode）、device_size_bytes（标签 device）。
//!
//! Go 侧的 ioctl 设备统计分支依赖 dennwc/btrfs FFI，不移植：恒走
//! ioctl 失败时的回退分支（仅 device_size_bytes，无 device_unused_bytes
//! 与 device_errors_total），与原版在无权限环境下的输出一致。
//!
//! 偏离点：
//! - 布局（raid0/raid1/…）与设备按名称字典序输出（Go map 遍历无序）；
//! - fs/btrfs 目录缺失时返回空指标族（Go 侧 glob 无匹配同样无输出）；
//! - SysReadFile 语义（128 字节上限、拒绝 NUL、TrimSpace）本地复刻
//!   （powersupplyclass 的实现未跨模块公开），文件不存在按 Go readFile
//!   语义忽略（返回空串→数值按 0）；目录列表（devices/layouts/features）
//!   读取失败为致命错误（对齐 Go listFiles）；
//! - 仅读取采集器消费的文件（global_rsv_reserved 等未消费文件不读）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// Btrfs 目录（相对 sys_path）
const BTRFS_DIR: &str = "fs/btrfs";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;
/// 对齐 procfs readDeviceInfo 的固定扇区大小（procfs.SectorSize）
const SECTOR_SIZE: u64 = 512;
/// 块组类型（对齐 Go getMetrics 的 data/metadata/system 顺序）
const BLOCK_GROUP_TYPES: [&str; 3] = ["data", "metadata", "system"];

pub struct BtrfsCollector {
    sys_path: PathBuf,
}

impl BtrfsCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for BtrfsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个布局（raid 模式）的用量统计
#[derive(Debug, Default)]
struct LayoutUsage {
    total_bytes: u64,
    used_bytes: u64,
    ratio: f64,
}

/// 单个块组类型（data/metadata/system）的分配统计
#[derive(Debug, Default)]
struct AllocationStats {
    reserved_bytes: u64,
    // 布局按名称字典序（Go 为 map 遍历，此处排序保证输出稳定）
    layouts: Vec<(String, LayoutUsage)>,
}

/// 提交统计（commit_stats 文件缺失时为全零，对齐 btrfs < 6.0）
#[derive(Debug, Default)]
struct CommitStats {
    commits: u64,
    last_commit_ms: u64,
    max_commit_ms: u64,
    total_commit_ms: u64,
}

/// 单个 Btrfs 文件系统的统计
#[derive(Debug, Default)]
struct FsStats {
    uuid: String,
    label: String,
    global_rsv_size: u64,
    data: AllocationStats,
    metadata: AllocationStats,
    system: AllocationStats,
    // (设备名, 设备字节大小)，按设备名字典序
    devices: Vec<(String, u64)>,
    commit_stats: CommitStats,
}

/// 对齐 procfs SysReadFile：最多读 128 字节、拒绝 NUL 字节、去除首尾
/// 空白；文件不存在按 Go readFile 语义忽略（返回空串）
fn read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: BTRFS_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 对齐 Go readValue：读取数值文件，解析失败按 0（仅文件不存在被
/// 容忍，其他读取错误为致命错误）
fn read_u64(path: &Path) -> Result<u64, CollectorError> {
    let text = read_file(path)?;
    Ok(text.parse::<u64>().unwrap_or(0))
}

/// 目录条目按名称字典序（对齐 filepath.Glob / 输出稳定性）
fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>, CollectorError> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    Ok(entries)
}

/// 对齐 Go calcRatio：布局模式的分配比例（raid5/raid6 依赖设备数）
fn calc_ratio(mode: &str, dev_count: usize) -> f64 {
    match mode {
        "single" | "raid0" => 1.0,
        "dup" | "raid1" | "raid10" => 2.0,
        "raid1c3" => 3.0,
        "raid1c4" => 4.0,
        "raid5" => dev_count as f64 / (dev_count as f64 - 1.0),
        "raid6" => dev_count as f64 / (dev_count as f64 - 2.0),
        _ => 0.0,
    }
}

/// 读取块组类型的分配统计（对齐 Go readAllocationStats + readLayouts：
/// 仅目录子项视为布局）
fn read_allocation(dir: &Path, dev_count: usize) -> Result<AllocationStats, CollectorError> {
    let reserved_bytes = read_u64(&dir.join("bytes_reserved"))?;
    let mut layouts = Vec::new();
    for entry in sorted_entries(dir)? {
        if !entry.is_dir() {
            continue;
        }
        let mode = entry
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let usage = LayoutUsage {
            total_bytes: read_u64(&entry.join("total_bytes"))?,
            used_bytes: read_u64(&entry.join("used_bytes"))?,
            ratio: calc_ratio(&mode, dev_count),
        };
        layouts.push((mode, usage));
    }
    Ok(AllocationStats {
        reserved_bytes,
        layouts,
    })
}

/// 读取 commit_stats（对齐 Go readCommitStats：文件缺失为全零，
/// 行格式必须为 "<key> <value>"，未知键忽略）
fn read_commit_stats(path: &Path) -> Result<CommitStats, CollectorError> {
    let mut stats = CommitStats::default();
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        // commit_stats 不存在（btrfs 版本 < 6.0）→ 零值
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(stats),
        Err(error) => return Err(error.into()),
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(CollectorError::Parse {
                file: BTRFS_DIR,
                reason: format!("invalid commit_stats line {line:?}"),
            });
        }
        let value = parts[1]
            .parse::<u64>()
            .map_err(|error| CollectorError::Parse {
                file: BTRFS_DIR,
                reason: format!("error parsing commit_stats line: {error}"),
            })?;
        match parts[0] {
            "commits" => stats.commits = value,
            "last_commit_ms" => stats.last_commit_ms = value,
            "max_commit_ms" => stats.max_commit_ms = value,
            "total_commit_ms" => stats.total_commit_ms = value,
            _ => {}
        }
    }
    Ok(stats)
}

/// 读取单个文件系统的统计（对齐 Go readFilesystemStats；设备列表
/// 目录或分配目录缺失为致命错误）
fn read_fs_stats(fs_dir: &Path) -> Result<FsStats, CollectorError> {
    // 设备信息（对齐 Go readDeviceInfo：size 缺失按 0，大小 =
    // 扇区大小 × size 文件值）
    let mut devices = Vec::new();
    for entry in sorted_entries(&fs_dir.join("devices"))? {
        let name = entry
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let size = SECTOR_SIZE * read_u64(&entry.join("size"))?;
        devices.push((name, size));
    }
    let dev_count = devices.len();

    let mut uuid = read_file(&fs_dir.join("metadata_uuid"))?;
    // UUID 取不到时回退为目录基名（对齐 Go FS.Stats）
    if uuid.is_empty() {
        uuid = fs_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
    }

    Ok(FsStats {
        label: read_file(&fs_dir.join("label"))?,
        uuid,
        global_rsv_size: read_u64(&fs_dir.join("allocation/global_rsv_size"))?,
        data: read_allocation(&fs_dir.join("allocation/data"), dev_count)?,
        metadata: read_allocation(&fs_dir.join("allocation/metadata"), dev_count)?,
        system: read_allocation(&fs_dir.join("allocation/system"), dev_count)?,
        devices,
        commit_stats: read_commit_stats(&fs_dir.join("commit_stats"))?,
    })
}

impl Collector for BtrfsCollector {
    fn name(&self) -> &'static str {
        "btrfs"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let btrfs_dir = self.sys_path.join(BTRFS_DIR);
        // glob fs/btrfs/*-*：仅名称含 '-' 的目录为文件系统
        let mut fs_dirs: Vec<PathBuf> = match std::fs::read_dir(&btrfs_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.is_dir()
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.contains('-'))
                })
                .collect(),
            // fs/btrfs 目录缺失（无 Btrfs 文件系统）→ 无样本
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        // 对齐 filepath.Glob 的字典序
        fs_dirs.sort();
        if fs_dirs.is_empty() {
            return Ok(Vec::new());
        }

        // 预建 11 个指标族（顺序对齐 Go getMetrics 的推送序）
        let mut info = MetricFamily::new(
            "node_btrfs_info",
            "Filesystem information",
            MetricType::Gauge,
        );
        let mut global_rsv = MetricFamily::new(
            "node_btrfs_global_rsv_size_bytes",
            "Size of global reserve.",
            MetricType::Gauge,
        );
        let mut commits = MetricFamily::new(
            "node_btrfs_commits_total",
            "The total number of commits that have occurred.",
            MetricType::Counter,
        );
        let mut last_commit = MetricFamily::new(
            "node_btrfs_last_commit_seconds",
            "Duration of the most recent commit, in seconds.",
            MetricType::Gauge,
        );
        let mut max_commit = MetricFamily::new(
            "node_btrfs_max_commit_seconds",
            "Duration of the slowest commit, in seconds.",
            MetricType::Gauge,
        );
        let mut commit_total = MetricFamily::new(
            "node_btrfs_commit_seconds_total",
            "Sum of the duration of all commits, in seconds.",
            MetricType::Counter,
        );
        let mut reserved = MetricFamily::new(
            "node_btrfs_reserved_bytes",
            "Amount of space reserved for a data type",
            MetricType::Gauge,
        );
        let mut used = MetricFamily::new(
            "node_btrfs_used_bytes",
            "Amount of used space by a layout/data type",
            MetricType::Gauge,
        );
        let mut size = MetricFamily::new(
            "node_btrfs_size_bytes",
            "Amount of space allocated for a layout/data type",
            MetricType::Gauge,
        );
        let mut ratio = MetricFamily::new(
            "node_btrfs_allocation_ratio",
            "Data allocation ratio for a layout/data type",
            MetricType::Gauge,
        );
        let mut device_size = MetricFamily::new(
            "node_btrfs_device_size_bytes",
            "Size of a device that is part of the filesystem.",
            MetricType::Gauge,
        );

        for fs_dir in fs_dirs {
            let stats = read_fs_stats(&fs_dir)?;
            let uuid = ("uuid".to_string(), stats.uuid.clone());

            info.push_labeled(
                vec![uuid.clone(), ("label".to_string(), stats.label.clone())],
                1.0,
            );
            global_rsv.push_labeled(vec![uuid.clone()], stats.global_rsv_size as f64);
            commits.push_labeled(vec![uuid.clone()], stats.commit_stats.commits as f64);
            last_commit.push_labeled(
                vec![uuid.clone()],
                stats.commit_stats.last_commit_ms as f64 / 1000.0,
            );
            max_commit.push_labeled(
                vec![uuid.clone()],
                stats.commit_stats.max_commit_ms as f64 / 1000.0,
            );
            commit_total.push_labeled(
                vec![uuid.clone()],
                stats.commit_stats.total_commit_ms as f64 / 1000.0,
            );

            for bgt in BLOCK_GROUP_TYPES {
                let allocation = match bgt {
                    "data" => &stats.data,
                    "metadata" => &stats.metadata,
                    _ => &stats.system,
                };
                let mut labels = vec![uuid.clone()];
                labels.push(("block_group_type".to_string(), bgt.to_string()));
                reserved.push_labeled(labels.clone(), allocation.reserved_bytes as f64);
                for (mode, usage) in &allocation.layouts {
                    let mut layout_labels = labels.clone();
                    layout_labels.push(("mode".to_string(), mode.clone()));
                    used.push_labeled(layout_labels.clone(), usage.used_bytes as f64);
                    size.push_labeled(layout_labels.clone(), usage.total_bytes as f64);
                    ratio.push_labeled(layout_labels, usage.ratio);
                }
            }

            // ioctl 回退分支：仅设备大小（对齐 Go ioctlStats == nil 分支）
            for (device, size_bytes) in &stats.devices {
                device_size.push_labeled(
                    vec![uuid.clone(), ("device".to_string(), device.clone())],
                    *size_bytes as f64,
                );
            }
        }

        Ok(vec![
            info,
            global_rsv,
            commits,
            last_commit,
            max_commit,
            commit_total,
            reserved,
            used,
            size,
            ratio,
            device_size,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    /// 按名称定位指标族
    fn family_of<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|family| family.name == name)
            .unwrap_or_else(|| panic!("缺少指标族 {name}"))
    }

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

    const UUID1: &str = "0abb23a9-579b-43e6-ad30-227ef47fcb9d";
    const UUID2: &str = "7f07c59f-6136-449c-ab87-e1cf2328731b";

    #[test]
    fn test_collect_matches_fixture() {
        let collector = BtrfsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 11);

        // info：标签顺序 uuid、label，两个文件系统按 UUID 字典序
        let info = family_of(&families, "node_btrfs_info");
        assert_eq!(info.mtype, MetricType::Gauge);
        assert_eq!(info.samples.len(), 2);
        assert_eq!(
            info.samples[0].labels,
            vec![
                ("uuid".to_string(), UUID1.to_string()),
                ("label".to_string(), "fixture".to_string()),
            ]
        );
        assert_eq!(
            info.samples[1].labels,
            vec![
                ("uuid".to_string(), UUID2.to_string()),
                ("label".to_string(), String::new()),
            ]
        );

        // 基础指标（黄金值对齐 Go TestBtrfs）
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_global_rsv_size_bytes"),
                &[("uuid", UUID1)]
            ),
            1.6777216e7
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_commits_total"),
                &[("uuid", UUID1)]
            ),
            258051.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_commits_total"),
                &[("uuid", UUID2)]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_last_commit_seconds"),
                &[("uuid", UUID1)]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_max_commit_seconds"),
                &[("uuid", UUID1)]
            ),
            51.462
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_btrfs_commit_seconds_total"),
                &[("uuid", UUID1)]
            ),
            47836.09
        );

        // 分配统计：FS1 raid0/raid1、FS2 raid5/raid6（布局字典序）
        let used = family_of(&families, "node_btrfs_used_bytes");
        assert_eq!(used.samples.len(), 6);
        assert_eq!(
            value_of(
                used,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "data"),
                    ("mode", "raid0")
                ]
            ),
            8.08189952e8
        );
        assert_eq!(
            value_of(
                used,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "metadata"),
                    ("mode", "raid1")
                ]
            ),
            933888.0
        );
        assert_eq!(
            value_of(
                used,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "system"),
                    ("mode", "raid1")
                ]
            ),
            16384.0
        );
        assert_eq!(
            value_of(
                used,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "data"),
                    ("mode", "raid5")
                ]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                used,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "metadata"),
                    ("mode", "raid6")
                ]
            ),
            114688.0
        );

        let size = family_of(&families, "node_btrfs_size_bytes");
        assert_eq!(
            value_of(
                size,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "data"),
                    ("mode", "raid0")
                ]
            ),
            2.147483648e9
        );
        assert_eq!(
            value_of(
                size,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "data"),
                    ("mode", "raid5")
                ]
            ),
            6.44087808e8
        );
        assert_eq!(
            value_of(
                size,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "metadata"),
                    ("mode", "raid6")
                ]
            ),
            4.29391872e8
        );
        assert_eq!(
            value_of(
                size,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "system"),
                    ("mode", "raid6")
                ]
            ),
            1.6777216e7
        );

        let ratio = family_of(&families, "node_btrfs_allocation_ratio");
        assert_eq!(
            value_of(
                ratio,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "data"),
                    ("mode", "raid0")
                ]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                ratio,
                &[
                    ("uuid", UUID1),
                    ("block_group_type", "metadata"),
                    ("mode", "raid1")
                ]
            ),
            2.0
        );
        // raid5：4 设备 → 4/3
        assert_eq!(
            value_of(
                ratio,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "data"),
                    ("mode", "raid5")
                ]
            ),
            1.3333333333333333
        );
        // raid6：4 设备 → 4/2
        assert_eq!(
            value_of(
                ratio,
                &[
                    ("uuid", UUID2),
                    ("block_group_type", "metadata"),
                    ("mode", "raid6")
                ]
            ),
            2.0
        );

        // 设备大小 = 512 × size 文件值，按设备名字典序
        let device_size = family_of(&families, "node_btrfs_device_size_bytes");
        assert_eq!(device_size.samples.len(), 6);
        assert_eq!(
            value_of(device_size, &[("uuid", UUID1), ("device", "loop25")]),
            1.073741824e10
        );
        assert_eq!(
            value_of(device_size, &[("uuid", UUID1), ("device", "loop26")]),
            1.073741824e10
        );
        assert_eq!(
            value_of(device_size, &[("uuid", UUID2), ("device", "loop22")]),
            1.073741824e10
        );
        assert_eq!(
            value_of(device_size, &[("uuid", UUID2), ("device", "loop25")]),
            1.073741824e10
        );
    }

    #[test]
    fn test_missing_dir_returns_empty() {
        let collector = BtrfsCollector::with_root(PathBuf::from("/nonexistent-foims-btrfs-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    #[test]
    fn test_parse_error_on_bad_commit_stats_line() {
        // 最小文件系统树：commit_stats 行格式非法 → Parse 错误（错误
        // 信息对齐 Go 原文 "invalid commit_stats line"）
        let root = std::env::temp_dir().join(format!("foims-btrfs-test-{}", std::process::id()));
        let fs_dir = root.join("fs/btrfs/00000000-0000-0000-0000-000000000000");
        for sub in [
            "devices",
            "allocation/data",
            "allocation/metadata",
            "allocation/system",
        ] {
            std::fs::create_dir_all(fs_dir.join(sub))
                .unwrap_or_else(|e| panic!("创建临时目录失败: {e}"));
        }
        std::fs::write(fs_dir.join("commit_stats"), "commits\n")
            .unwrap_or_else(|e| panic!("写入临时文件失败: {e}"));

        let collector = BtrfsCollector::with_root(root.clone());
        let result = collector.collect();
        assert!(
            matches!(&result, Err(CollectorError::Parse { file, reason })
                if *file == BTRFS_DIR && reason.starts_with("invalid commit_stats line")
            ),
            "期望 Parse 错误，实际 {result:?}"
        );

        std::fs::remove_dir_all(&root).unwrap_or_else(|e| panic!("清理临时目录失败: {e}"));
    }
}
