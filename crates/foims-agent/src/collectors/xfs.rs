//! xfs 采集器：XFS 文件系统运行时统计。
//!
//! 对齐 node_exporter `xfs_linux.go`（默认启用）+ procfs xfs 包
//! SysStats（glob /sys/fs/xfs/*/stats/stats）：每个文件系统输出
//! 39 个 Counter 族（前缀 node_xfs_，标签 device），取值来自
//! extent_alloc/abt/blk_map/bmbt/dir/ig/rw/vnodes 八个消费字段组。
//!
//! 偏离点：
//! - 仅校验消费的 8 个字段组（Go ParseStats 会校验全部已知字段组，
//!   trans/log/buf 等未消费组与 "gc xpc" 双词标签、xpc/defer_relog
//!   扩展精度组此处跳过不解析）；
//! - rw 行为 [write, read] 列序（procfs readWriteStats 的反直觉顺序，
//!   内核第一列是 write）：read_calls_total 取第二列、write_calls_total
//!   取第一列；
//! - vnodes 行接受 7 或 8 列（Free 列为内核新版本才有，未消费）；
//! - 文件系统按目录名字典序输出（与 filepath.Glob 字典序一致）；
//! - fs/xfs 目录缺失时返回空指标族（Go 侧 glob 无匹配同样无输出）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// XFS 统计目录（相对 sys_path）
const XFS_DIR: &str = "fs/xfs";

pub struct XfsCollector {
    sys_path: PathBuf,
}

impl XfsCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for XfsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个 XFS 文件系统的统计（仅采集器消费的 8 个字段组，字段名沿用
/// 内核输出标签；rw[0] 为第一列 write，rw[1] 为第二列 read）
#[derive(Debug, Default)]
struct XfsStats {
    extent_alloc: [u32; 4],
    abt: [u32; 4],
    blk_map: [u32; 7],
    bmbt: [u32; 4],
    dir: [u32; 4],
    ig: [u32; 7],
    rw: [u32; 2],
    vnodes: [u32; 7],
}

/// 指标取值函数类型（从解析结果取值）
type StatsValueFn = fn(&XfsStats) -> f64;

/// 39 个指标族的（名称后缀, help, 取值函数）表，顺序逐字对齐
/// Go updateXFSStats 的 metrics 表（名称/help 为 Go 上游英文原文）
const METRICS: [(&str, &str, StatsValueFn); 39] = [
    (
        "extent_allocation_extents_allocated_total",
        "Number of extents allocated for a filesystem.",
        |s| f64::from(s.extent_alloc[0]),
    ),
    (
        "extent_allocation_blocks_allocated_total",
        "Number of blocks allocated for a filesystem.",
        |s| f64::from(s.extent_alloc[1]),
    ),
    (
        "extent_allocation_extents_freed_total",
        "Number of extents freed for a filesystem.",
        |s| f64::from(s.extent_alloc[2]),
    ),
    (
        "extent_allocation_blocks_freed_total",
        "Number of blocks freed for a filesystem.",
        |s| f64::from(s.extent_alloc[3]),
    ),
    (
        "allocation_btree_lookups_total",
        "Number of allocation B-tree lookups for a filesystem.",
        |s| f64::from(s.abt[0]),
    ),
    (
        "allocation_btree_compares_total",
        "Number of allocation B-tree compares for a filesystem.",
        |s| f64::from(s.abt[1]),
    ),
    (
        "allocation_btree_records_inserted_total",
        "Number of allocation B-tree records inserted for a filesystem.",
        |s| f64::from(s.abt[2]),
    ),
    (
        "allocation_btree_records_deleted_total",
        "Number of allocation B-tree records deleted for a filesystem.",
        |s| f64::from(s.abt[3]),
    ),
    (
        "block_mapping_reads_total",
        "Number of block map for read operations for a filesystem.",
        |s| f64::from(s.blk_map[0]),
    ),
    (
        "block_mapping_writes_total",
        "Number of block map for write operations for a filesystem.",
        |s| f64::from(s.blk_map[1]),
    ),
    (
        "block_mapping_unmaps_total",
        "Number of block unmaps (deletes) for a filesystem.",
        |s| f64::from(s.blk_map[2]),
    ),
    (
        "block_mapping_extent_list_insertions_total",
        "Number of extent list insertions for a filesystem.",
        |s| f64::from(s.blk_map[3]),
    ),
    (
        "block_mapping_extent_list_deletions_total",
        "Number of extent list deletions for a filesystem.",
        |s| f64::from(s.blk_map[4]),
    ),
    (
        "block_mapping_extent_list_lookups_total",
        "Number of extent list lookups for a filesystem.",
        |s| f64::from(s.blk_map[5]),
    ),
    (
        "block_mapping_extent_list_compares_total",
        "Number of extent list compares for a filesystem.",
        |s| f64::from(s.blk_map[6]),
    ),
    (
        "block_map_btree_lookups_total",
        "Number of block map B-tree lookups for a filesystem.",
        |s| f64::from(s.bmbt[0]),
    ),
    (
        "block_map_btree_compares_total",
        "Number of block map B-tree compares for a filesystem.",
        |s| f64::from(s.bmbt[1]),
    ),
    (
        "block_map_btree_records_inserted_total",
        "Number of block map B-tree records inserted for a filesystem.",
        |s| f64::from(s.bmbt[2]),
    ),
    (
        "block_map_btree_records_deleted_total",
        "Number of block map B-tree records deleted for a filesystem.",
        |s| f64::from(s.bmbt[3]),
    ),
    (
        "directory_operation_lookup_total",
        "Number of file name directory lookups which miss the operating systems directory name lookup cache.",
        |s| f64::from(s.dir[0]),
    ),
    (
        "directory_operation_create_total",
        "Number of times a new directory entry was created for a filesystem.",
        |s| f64::from(s.dir[1]),
    ),
    (
        "directory_operation_remove_total",
        "Number of times an existing directory entry was created for a filesystem.",
        |s| f64::from(s.dir[2]),
    ),
    (
        "directory_operation_getdents_total",
        "Number of times the directory getdents operation was performed for a filesystem.",
        |s| f64::from(s.dir[3]),
    ),
    (
        "inode_operation_attempts_total",
        "Number of times the OS looked for an XFS inode in the inode cache.",
        |s| f64::from(s.ig[0]),
    ),
    (
        "inode_operation_found_total",
        "Number of times the OS looked for and found an XFS inode in the inode cache.",
        |s| f64::from(s.ig[1]),
    ),
    (
        "inode_operation_recycled_total",
        "Number of times the OS found an XFS inode in the cache, but could not use it as it was being recycled.",
        |s| f64::from(s.ig[2]),
    ),
    (
        "inode_operation_missed_total",
        "Number of times the OS looked for an XFS inode in the cache, but did not find it.",
        |s| f64::from(s.ig[3]),
    ),
    (
        "inode_operation_duplicates_total",
        "Number of times the OS tried to add a missing XFS inode to the inode cache, but found it had already been added by another process.",
        |s| f64::from(s.ig[4]),
    ),
    (
        "inode_operation_reclaims_total",
        "Number of times the OS reclaimed an XFS inode from the inode cache to free memory for another purpose.",
        |s| f64::from(s.ig[5]),
    ),
    (
        "inode_operation_attribute_changes_total",
        "Number of times the OS explicitly changed the attributes of an XFS inode.",
        |s| f64::from(s.ig[6]),
    ),
    (
        "read_calls_total",
        "Number of read(2) system calls made to files in a filesystem.",
        |s| f64::from(s.rw[1]),
    ),
    (
        "write_calls_total",
        "Number of write(2) system calls made to files in a filesystem.",
        |s| f64::from(s.rw[0]),
    ),
    (
        "vnode_active_total",
        "Number of vnodes not on free lists for a filesystem.",
        |s| f64::from(s.vnodes[0]),
    ),
    (
        "vnode_allocate_total",
        "Number of times vn_alloc called for a filesystem.",
        |s| f64::from(s.vnodes[1]),
    ),
    (
        "vnode_get_total",
        "Number of times vn_get called for a filesystem.",
        |s| f64::from(s.vnodes[2]),
    ),
    (
        "vnode_hold_total",
        "Number of times vn_hold called for a filesystem.",
        |s| f64::from(s.vnodes[3]),
    ),
    (
        "vnode_release_total",
        "Number of times vn_rele called for a filesystem.",
        |s| f64::from(s.vnodes[4]),
    ),
    (
        "vnode_reclaim_total",
        "Number of times vn_reclaim called for a filesystem.",
        |s| f64::from(s.vnodes[5]),
    ),
    (
        "vnode_remove_total",
        "Number of times vn_remove called for a filesystem.",
        |s| f64::from(s.vnodes[6]),
    ),
];

/// 解析一组 uint32 统计值（对齐 Go parsers.ParseUint32s）
fn parse_uint32s(fields: &[&str]) -> Result<Vec<u32>, CollectorError> {
    fields
        .iter()
        .map(|field| {
            field.parse::<u32>().map_err(|error| CollectorError::Parse {
                file: XFS_DIR,
                reason: format!("统计值解析失败: {error}"),
            })
        })
        .collect()
}

/// 校验字段组数量并填充目标数组（错误信息逐字对齐 Go 各 stats 构造
/// 函数；vnodes 组允许 7 或 8 列）
fn fill_group(
    dest: &mut [u32],
    values: &[u32],
    allowed: &[usize],
    desc: &str,
) -> Result<(), CollectorError> {
    if !allowed.contains(&values.len()) {
        return Err(CollectorError::Parse {
            file: XFS_DIR,
            reason: format!(
                "incorrect number of values for XFS {desc}: {}",
                values.len()
            ),
        });
    }
    dest.copy_from_slice(&values[..dest.len()]);
    Ok(())
}

/// 解析 stats 文件内容（对齐 procfs xfs.ParseStats：仅处理消费的
/// 8 个字段组，其余组跳过）
fn parse_stats(text: &str) -> Result<XfsStats, CollectorError> {
    let mut stats = XfsStats::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let values = parse_uint32s(&fields[1..])?;
        match fields[0] {
            "extent_alloc" => {
                fill_group(
                    &mut stats.extent_alloc,
                    &values,
                    &[4],
                    "extent allocation stats",
                )?;
            }
            "abt" | "bmbt" => {
                let group = if fields[0] == "abt" {
                    &mut stats.abt
                } else {
                    &mut stats.bmbt
                };
                fill_group(group, &values, &[4], "btree stats")?;
            }
            "blk_map" => {
                fill_group(&mut stats.blk_map, &values, &[7], "block mapping stats")?;
            }
            "dir" => {
                fill_group(&mut stats.dir, &values, &[4], "directory operation stats")?;
            }
            "ig" => {
                fill_group(&mut stats.ig, &values, &[7], "inode operation stats")?;
            }
            "rw" => {
                fill_group(&mut stats.rw, &values, &[2], "read write stats")?;
            }
            "vnodes" => {
                fill_group(&mut stats.vnodes, &values, &[7, 8], "vnode stats")?;
            }
            // 其余字段组（含 "gc xpc" 双词标签）不被采集器消费，跳过
            _ => {}
        }
    }
    Ok(stats)
}

impl Collector for XfsCollector {
    fn name(&self) -> &'static str {
        "xfs"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let xfs_dir = self.sys_path.join(XFS_DIR);
        let mut device_dirs: Vec<PathBuf> = match std::fs::read_dir(&xfs_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.is_dir())
                .collect(),
            // fs/xfs 目录缺失（无 XFS 文件系统）→ 无样本
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        // 对齐 filepath.Glob 的字典序
        device_dirs.sort();
        if device_dirs.is_empty() {
            return Ok(Vec::new());
        }

        // 预建 39 个指标族（顺序对齐 Go metrics 表）
        let mut families: Vec<MetricFamily> = METRICS
            .iter()
            .map(|(name, help, _)| {
                MetricFamily::new(&format!("node_xfs_{name}"), help, MetricType::Counter)
            })
            .collect();

        for device_dir in device_dirs {
            // glob 仅匹配存在 stats/stats 的目录
            let stats_path = device_dir.join("stats/stats");
            if !stats_path.exists() {
                continue;
            }
            let device = device_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            let text = std::fs::read_to_string(&stats_path)?;
            let stats = parse_stats(&text)?;
            for (index, (_, _, value)) in METRICS.iter().enumerate() {
                families[index]
                    .push_labeled(vec![("device".to_string(), device.clone())], value(&stats));
            }
        }

        Ok(families)
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

    /// 取无多标签族的唯一样本值
    fn value_of(family: &MetricFamily) -> f64 {
        assert_eq!(family.samples.len(), 1);
        family.samples[0].value
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = XfsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 39);

        // 族名与标签
        assert_eq!(
            families[0].name,
            "node_xfs_extent_allocation_extents_allocated_total"
        );
        assert_eq!(
            families[0].help,
            "Number of extents allocated for a filesystem."
        );
        assert_eq!(families[0].mtype, MetricType::Counter);
        assert_eq!(
            families[0].samples[0].labels,
            vec![("device".to_string(), "sda1".to_string())]
        );

        // 逐组黄金值（fixture sys/fs/xfs/sda1/stats/stats）
        let value = |index: usize| value_of(&families[index]);
        assert_eq!(value(0), 1.0);
        assert_eq!(value(1), 872.0);
        assert_eq!(value(2), 0.0);
        assert_eq!(value(3), 0.0);
        assert_eq!(value(8), 61.0);
        assert_eq!(value(9), 29.0);
        assert_eq!(value(13), 91.0);
        assert_eq!(value(19), 3.0);
        assert_eq!(value(20), 2.0);
        assert_eq!(value(21), 1.0);
        assert_eq!(value(22), 52.0);
        assert_eq!(value(23), 5.0);
        assert_eq!(value(24), 1.0);
        assert_eq!(value(26), 4.0);
        assert_eq!(value(29), 1.0);
        // rw 行列序反转：fixture "rw 28 0" → read=0 / write=28（对齐 e2e 黄金输出）
        assert_eq!(
            family_of(&families, "node_xfs_read_calls_total").samples[0].value,
            0.0
        );
        assert_eq!(
            family_of(&families, "node_xfs_write_calls_total").samples[0].value,
            28.0
        );
        // vnodes 组
        assert_eq!(value(32), 4.0);
        assert_eq!(value(36), 1.0);
        assert_eq!(value(37), 1.0);
        assert_eq!(value(38), 1.0);
    }

    #[test]
    fn test_missing_dir_returns_empty() {
        let collector = XfsCollector::with_root(PathBuf::from("/nonexistent-foims-xfs-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    #[test]
    fn test_parse_error_on_bad_group_count() {
        // extent_alloc 组列数错误 → Parse 错误（错误信息对齐 Go 原文）
        let root = std::env::temp_dir().join(format!("foims-xfs-test-{}", std::process::id()));
        let stats_dir = root.join("fs/xfs/sda1/stats");
        std::fs::create_dir_all(&stats_dir).unwrap_or_else(|e| panic!("创建临时目录失败: {e}"));
        std::fs::write(stats_dir.join("stats"), "extent_alloc 1 2\n")
            .unwrap_or_else(|e| panic!("写入临时文件失败: {e}"));

        let collector = XfsCollector::with_root(root.clone());
        let result = collector.collect();
        assert!(
            matches!(&result, Err(CollectorError::Parse { file, reason })
                if *file == XFS_DIR
                    && reason == "incorrect number of values for XFS extent allocation stats: 2"
            ),
            "期望 Parse 错误，实际 {result:?}"
        );

        std::fs::remove_dir_all(&root).unwrap_or_else(|e| panic!("清理临时目录失败: {e}"));
    }
}
