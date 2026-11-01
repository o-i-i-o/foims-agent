//! zfs 采集器：ZFS kstat 统计（/proc/spl/kstat/zfs）。
//!
//! 对齐 node_exporter `zfs_linux.go`（默认启用）：
//! - 11 个子系统 kstat 文件（子系统名 → 文件名映射逐字对齐 Go
//!   linuxPathMap）：头部 `name type data` 之后每行输出一条
//!   `node_<子系统>_<行名>`（Untyped，help 为完整 sysctl 键，行名中
//!   '-' 替换为 '_'，type 列仅接受 3=int64 / 4=uint64）；
//! - 池 io 统计（表头 ≥12 字段且首字段为 nread）：`node_zfs_zpool_<字段>`
//!   （标签 zpool）；
//! - 池 objset 统计：`node_zfs_zpool_dataset_<字段>`（标签 zpool+dataset，
//!   dataset 名从原行截取、保留值内空格）；
//! - 池状态：`node_zfs_zpool_state`（Gauge，标签 zpool+state，7 个状态
//!   逐一输出 0/1 标记）。
//!
//! 偏离点：
//! - 子系统按 Go linuxPathMap 字面量的声明序输出（Go map 遍历无序）；
//! - 池目录与 objset 文件按名称字典序输出（与 filepath.Glob 字典序
//!   一致）；
//! - spl/kstat/zfs 基目录不可打开或子系统/池文件打开失败时返回空指标
//!   族（对齐 Go errZFSNotAvailable/ErrNoData 语义）；解析失败仍返回
//!   Parse 错误；
//! - io 数据行字段数少于表头时返回 Parse 错误（Go 侧索引越界 panic）。

use std::io::Read;
use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// ZFS kstat 基目录（相对 proc_path）
const ZFS_DIR: &str = "spl/kstat/zfs";
/// kstat 数据类型：int64（对齐 Go kstatDataInt64）
const KSTAT_INT64: &str = "3";
/// kstat 数据类型：uint64（对齐 Go kstatDataUint64）
const KSTAT_UINT64: &str = "4";
/// 池状态名（顺序对齐 Go zfsPoolStatesName）
const POOL_STATES: [&str; 7] = [
    "online",
    "degraded",
    "faulted",
    "offline",
    "removed",
    "unavail",
    "suspended",
];
/// 子系统名 → kstat 文件名（顺序对齐 Go linuxPathMap 字面量声明序）
const SUBSYSTEMS: [(&str, &str); 11] = [
    ("zfs_abd", "abdstats"),
    ("zfs_arc", "arcstats"),
    ("zfs_dbuf", "dbufstats"),
    ("zfs_dmu_tx", "dmu_tx"),
    ("zfs_dnode", "dnodestats"),
    ("zfs_fm", "fm"),
    ("zfs_vdev_cache", "vdev_cache_stats"),
    ("zfs_vdev_mirror", "vdev_mirror_stats"),
    ("zfs_xuio", "xuio_stats"),
    ("zfs_zfetch", "zfetchstats"),
    ("zfs_zil", "zil"),
];

pub struct ZfsCollector {
    proc_path: PathBuf,
}

impl ZfsCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for ZfsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 在族列表中查找同名族，不存在则追加（池指标跨文件聚合到同族）
fn family_of<'a>(
    families: &'a mut Vec<MetricFamily>,
    name: &str,
    help: &str,
    mtype: MetricType,
) -> &'a mut MetricFamily {
    if let Some(index) = families.iter().position(|family| family.name == name) {
        return &mut families[index];
    }
    families.push(MetricFamily::new(name, help, mtype));
    let last = families.len() - 1;
    &mut families[last]
}

/// 解析 uint64 值（错误信息对齐 Go parseProcfsFile 原文）
fn parse_uint64(key: &str, raw: &str) -> Result<u64, CollectorError> {
    raw.parse::<u64>().map_err(|error| CollectorError::Parse {
        file: ZFS_DIR,
        reason: format!("could not parse expected unsigned integer value for {key:?}: {error}"),
    })
}

/// 解析 int64 值（错误信息对齐 Go parseProcfsFile 原文）
fn parse_int64(key: &str, raw: &str) -> Result<i64, CollectorError> {
    raw.parse::<i64>().map_err(|error| CollectorError::Parse {
        file: ZFS_DIR,
        reason: format!("could not parse expected signed integer value for {key:?}: {error}"),
    })
}

/// 解析子系统 kstat 文件（对齐 Go parseProcfsFile：头部 name/type/data
/// 之后，type 3/4 的行各输出一条指标；未出现头部为解析错误）
fn parse_subsystem_file(
    text: &str,
    file_name: &str,
    subsystem: &str,
    families: &mut Vec<MetricFamily>,
) -> Result<(), CollectorError> {
    let mut parse_line = false;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parse_line {
            if parts.len() == 3 && parts[0] == "name" && parts[1] == "type" && parts[2] == "data" {
                parse_line = true;
            }
            continue;
        }
        if parts.len() < 3 {
            continue;
        }
        let key = format!("kstat.zfs.misc.{file_name}.{}", parts[0]);
        let value = match parts[1] {
            KSTAT_UINT64 => parse_uint64(&key, parts[2])? as f64,
            KSTAT_INT64 => parse_int64(&key, parts[2])? as f64,
            // 其他 kstat 类型忽略（对齐 Go 的 TODO 分支）
            _ => continue,
        };
        // 族名取 sysctl 键最后一段（'-' → '_'），help 为完整键
        let metric_name = key.rsplit('.').next().unwrap_or_default().replace('-', "_");
        let family = family_of(
            families,
            &format!("node_{subsystem}_{metric_name}"),
            &key,
            MetricType::Untyped,
        );
        family.push(value);
    }
    if !parse_line {
        return Err(CollectorError::Parse {
            file: ZFS_DIR,
            reason: format!("did not parse a single {file_name:?} metric"),
        });
    }
    Ok(())
}

/// 解析池 io 文件（对齐 Go parsePoolProcfsFile：表头 ≥12 字段且首字段
/// 为 nread，数据行按表头逐字段解析；数据行短于表头时 Go 侧 panic，
/// 此处返回 Parse 错误）
fn parse_pool_io(
    text: &str,
    pool: &str,
    families: &mut Vec<MetricFamily>,
) -> Result<(), CollectorError> {
    let mut fields: Vec<&str> = Vec::new();
    let mut parse_line = false;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parse_line {
            if parts.len() >= 12 && parts[0] == "nread" {
                parse_line = true;
                fields = parts;
            }
            continue;
        }
        if parts.len() < fields.len() {
            return Err(CollectorError::Parse {
                file: ZFS_DIR,
                reason: format!("io 数据行字段数 {} 少于表头 {}", parts.len(), fields.len()),
            });
        }
        for (index, field) in fields.iter().enumerate() {
            let key = format!("kstat.zfs.misc.io.{field}");
            let value = parse_uint64(&key, parts[index])?;
            let metric_name = field.replace('-', "_");
            let family = family_of(
                families,
                &format!("node_zfs_zpool_{metric_name}"),
                &key,
                MetricType::Untyped,
            );
            family.push_labeled(vec![("zpool".to_string(), pool.to_string())], value as f64);
        }
    }
    Ok(())
}

/// 解析池 objset 文件（对齐 Go parsePoolObjsetFile：dataset_name 行的
/// 数据集名从原行截取、保留值内空格；仅 uint64 行输出指标）
fn parse_pool_objset(
    text: &str,
    pool: &str,
    families: &mut Vec<MetricFamily>,
) -> Result<(), CollectorError> {
    let mut parse_line = false;
    // 对齐 Go：池名/数据集名仅在遇到 dataset_name 行后才非空
    let mut pool_name = String::new();
    let mut dataset_name = String::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parse_line {
            if parts.len() == 3 && parts[0] == "name" && parts[1] == "type" && parts[2] == "data" {
                parse_line = true;
            }
            continue;
        }
        if parts.len() < 3 {
            continue;
        }
        if parts[0] == "dataset_name" {
            pool_name = pool.to_string();
            // 值可能含空格：从原行中该值的起始位置截取到行尾
            if let Some(position) = line.find(parts[2]) {
                dataset_name = line[position..].to_string();
            }
            continue;
        }
        if parts[1] == KSTAT_UINT64 {
            let key = format!("kstat.zfs.misc.objset.{}", parts[0]);
            let value = parts[2].parse::<u64>().map_err(|_| CollectorError::Parse {
                file: ZFS_DIR,
                reason: format!("could not parse expected integer value for {key:?}"),
            })?;
            let metric_name = parts[0].replace('-', "_");
            let family = family_of(
                families,
                &format!("node_zfs_zpool_dataset_{metric_name}"),
                &key,
                MetricType::Untyped,
            );
            family.push_labeled(
                vec![
                    ("zpool".to_string(), pool_name.clone()),
                    ("dataset".to_string(), dataset_name.clone()),
                ],
                value as f64,
            );
        }
    }
    if !parse_line {
        return Err(CollectorError::Parse {
            file: ZFS_DIR,
            reason: format!("did not parse a single {pool_name} {dataset_name} metric"),
        });
    }
    Ok(())
}

/// 解析池状态文件（对齐 Go parsePoolStateFile：首行为状态名（小写
/// 比较），7 个状态逐一输出 0/1 标记）
fn parse_pool_state(
    text: &str,
    pool: &str,
    families: &mut Vec<MetricFamily>,
) -> Result<(), CollectorError> {
    let actual_state = text.lines().next().unwrap_or("").to_lowercase();
    for state in POOL_STATES {
        let is_active = if actual_state == state { 1.0 } else { 0.0 };
        let family = family_of(
            families,
            "node_zfs_zpool_state",
            "kstat.zfs.misc.state",
            MetricType::Gauge,
        );
        family.push_labeled(
            vec![
                ("zpool".to_string(), pool.to_string()),
                ("state".to_string(), state.to_string()),
            ],
            is_active,
        );
    }
    Ok(())
}

impl Collector for ZfsCollector {
    fn name(&self) -> &'static str {
        "zfs"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let zfs_dir = self.proc_path.join(ZFS_DIR);
        // 基目录不可打开（zfs 模块未加载）→ ErrNoData 语义
        if std::fs::File::open(&zfs_dir).is_err() {
            return Ok(Vec::new());
        }

        let mut families: Vec<MetricFamily> = Vec::new();

        // 子系统 kstat：文件打开失败视为该特性不可用，跳过
        for (subsystem, file_name) in SUBSYSTEMS {
            let path = zfs_dir.join(file_name);
            let mut file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(_) => continue,
            };
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            parse_subsystem_file(&text, file_name, subsystem, &mut families)?;
        }

        // 池目录（字典序对齐 filepath.Glob）
        let mut pools: Vec<PathBuf> = std::fs::read_dir(&zfs_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect();
        pools.sort();
        let pool_names: Vec<String> = pools
            .iter()
            .map(|pool| {
                pool.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();

        // 池 io 统计（glob /*/io）
        for (pool, name) in pools.iter().zip(&pool_names) {
            let io_path = pool.join("io");
            if !io_path.exists() {
                continue;
            }
            let mut file = match std::fs::File::open(&io_path) {
                Ok(file) => file,
                // 池正在导出的竞态 → ErrNoData 语义
                Err(_) => return Ok(Vec::new()),
            };
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            parse_pool_io(&text, name, &mut families)?;
        }

        // 池 objset 统计（glob /*/objset-*）
        for (pool, name) in pools.iter().zip(&pool_names) {
            let mut objsets: Vec<PathBuf> = std::fs::read_dir(pool)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("objset-"))
                })
                .collect();
            objsets.sort();
            for objset in objsets {
                let mut file = match std::fs::File::open(&objset) {
                    Ok(file) => file,
                    Err(_) => return Ok(Vec::new()),
                };
                let mut text = String::new();
                file.read_to_string(&mut text)?;
                parse_pool_objset(&text, name, &mut families)?;
            }
        }

        // 池状态（glob /*/state）
        for (pool, name) in pools.iter().zip(&pool_names) {
            let state_path = pool.join("state");
            if !state_path.exists() {
                continue;
            }
            let mut file = match std::fs::File::open(&state_path) {
                Ok(file) => file,
                Err(_) => return Ok(Vec::new()),
            };
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            parse_pool_state(&text, name, &mut families)?;
        }

        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
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

    #[test]
    fn test_collect_matches_fixture() {
        let collector = ZfsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));

        // 259 条子系统 kstat 行 + 12 个 io 字段 + 6 个 objset 字段 + 1 状态族
        assert_eq!(families.len(), 278);

        // 子系统黄金值（对齐 Go 测试与 e2e 黄金输出；help 为完整 sysctl 键）
        let arc_hits = family_of(&families, "node_zfs_arc_hits");
        assert_eq!(arc_hits.help, "kstat.zfs.misc.arcstats.hits");
        assert_eq!(arc_hits.mtype, MetricType::Untyped);
        assert_eq!(arc_hits.samples[0].value, 8772612.0);
        // int64 负值（type 3）
        assert_eq!(
            family_of(&families, "node_zfs_arc_memory_available_bytes").samples[0].value,
            (-922337203685477580i64) as f64
        );
        assert_eq!(
            family_of(&families, "node_zfs_zfetch_hits").samples[0].value,
            7067992.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_zil_zil_commit_count").samples[0].value,
            10.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_vdev_cache_delegations").samples[0].value,
            40.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_xuio_onloan_read_buf").samples[0].value,
            32.0
        );
        // 行名中的 '-' 替换为 '_'
        let erpt = family_of(&families, "node_zfs_fm_erpt_dropped");
        assert_eq!(erpt.help, "kstat.zfs.misc.fm.erpt-dropped");
        assert_eq!(erpt.samples[0].value, 18.0);
        assert_eq!(
            family_of(&families, "node_zfs_dmu_tx_dmu_tx_assigned").samples[0].value,
            3532844.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_abd_linear_data_size").samples[0].value,
            223232.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_dbuf_hash_hits").samples[0].value,
            108807.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_dnode_dnode_hold_alloc_hits").samples[0].value,
            37617.0
        );
        assert_eq!(
            family_of(&families, "node_zfs_vdev_mirror_preferred_not_found").samples[0].value,
            94.0
        );

        // 池 io：pool1/pool3 各 1884160，poolz1 2826240（pool2 无 io 文件）
        let nread = family_of(&families, "node_zfs_zpool_nread");
        assert_eq!(nread.help, "kstat.zfs.misc.io.nread");
        assert_eq!(nread.samples.len(), 3);
        assert_eq!(value_of(nread, &[("zpool", "pool1")]), 1884160.0);
        assert_eq!(value_of(nread, &[("zpool", "pool3")]), 1884160.0);
        assert_eq!(value_of(nread, &[("zpool", "poolz1")]), 2826240.0);

        // 池 objset：6 个文件各 6 字段；数据集名保留原行内空格
        let writes = family_of(&families, "node_zfs_zpool_dataset_writes");
        assert_eq!(writes.help, "kstat.zfs.misc.objset.writes");
        assert_eq!(writes.samples.len(), 6);
        assert_eq!(
            value_of(writes, &[("zpool", "pool1"), ("dataset", "pool1")]),
            0.0
        );
        assert_eq!(
            value_of(writes, &[("zpool", "pool1"), ("dataset", "pool1/dataset1")]),
            4.0
        );
        assert_eq!(
            value_of(
                writes,
                &[("zpool", "pool3"), ("dataset", "pool3/dataset with  space")]
            ),
            4.0
        );
        assert_eq!(
            value_of(
                writes,
                &[("zpool", "poolz1"), ("dataset", "poolz1/dataset1")]
            ),
            10.0
        );

        // 池状态：4 池 × 7 状态；pool1=online、poolz1=degraded、pool2=suspended
        let state = family_of(&families, "node_zfs_zpool_state");
        assert_eq!(state.mtype, MetricType::Gauge);
        assert_eq!(state.samples.len(), 28);
        assert_eq!(
            value_of(state, &[("zpool", "pool1"), ("state", "online")]),
            1.0
        );
        assert_eq!(
            value_of(state, &[("zpool", "pool1"), ("state", "degraded")]),
            0.0
        );
        assert_eq!(
            value_of(state, &[("zpool", "poolz1"), ("state", "degraded")]),
            1.0
        );
        assert_eq!(
            value_of(state, &[("zpool", "pool2"), ("state", "suspended")]),
            1.0
        );
        assert_eq!(
            value_of(state, &[("zpool", "pool2"), ("state", "online")]),
            0.0
        );
    }

    #[test]
    fn test_missing_dir_returns_empty() {
        let collector = ZfsCollector::with_root(PathBuf::from("/nonexistent-foims-zfs-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    #[test]
    fn test_parse_error_on_bad_value() {
        // 基目录存在但 kstat 值列非法 → Parse 错误（错误信息对齐 Go 原文）
        let root = std::env::temp_dir().join(format!("foims-zfs-test-{}", std::process::id()));
        let zfs_dir = root.join("spl/kstat/zfs");
        std::fs::create_dir_all(&zfs_dir).unwrap_or_else(|e| panic!("创建临时目录失败: {e}"));
        std::fs::write(
            zfs_dir.join("fm"),
            "name type data\nerpt-dropped 4 not-a-number\n",
        )
        .unwrap_or_else(|e| panic!("写入临时文件失败: {e}"));

        let collector = ZfsCollector::with_root(root.clone());
        let result = collector.collect();
        assert!(
            matches!(&result, Err(CollectorError::Parse { file, reason })
                if *file == ZFS_DIR
                    && reason.starts_with(
                        "could not parse expected unsigned integer value for \
                         \"kstat.zfs.misc.fm.erpt-dropped\""
                    )
            ),
            "期望 Parse 错误，实际 {result:?}"
        );

        std::fs::remove_dir_all(&root).unwrap_or_else(|e| panic!("清理临时目录失败: {e}"));
    }
}
