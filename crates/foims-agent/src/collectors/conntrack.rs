//! conntrack 采集器：连接跟踪表。
//!
//! 对齐 node_exporter `conntrack_linux.go`（默认启用）：
//! - `node_nf_conntrack_entries` / `node_nf_conntrack_entries_limit` 来自
//!   /proc/sys/net/netfilter/nf_conntrack_{count,max}；模块未加载（文件缺失）
//!   时返回 NoData；
//! - `node_nf_conntrack_stat_*` 八项统计来自 /proc/net/stat/nf_conntrack
//!   逐 CPU 的十六进制计数（列偏移与聚合语义对齐 Go 源 + procfs：
//!   found=[2] invalid=[4] ignore=[5] insert=[8] insert_failed=[9] drop=[10]
//!   early_drop=[11] search_restart=[16]），表头行与列数不符的行跳过。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 连接跟踪计数/上限文件（相对 proc_path）
const COUNT_FILE: &str = "sys/net/netfilter/nf_conntrack_count";
const MAX_FILE: &str = "sys/net/netfilter/nf_conntrack_max";
/// 逐 CPU 统计文件（相对 proc_path）
const STAT_FILE: &str = "net/stat/nf_conntrack";

pub struct ConntrackCollector {
    proc_path: PathBuf,
}

impl ConntrackCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }

    /// 读取计数文件；缺失（nf_conntrack 模块未加载）时返回 NoData
    fn read_u64_file(&self, file: &str) -> Result<Option<u64>, CollectorError> {
        match std::fs::read_to_string(self.proc_path.join(file)) {
            Ok(text) => {
                text.trim()
                    .parse::<u64>()
                    .map(Some)
                    .map_err(|error| CollectorError::Parse {
                        file: COUNT_FILE,
                        reason: format!("{file} 内容非法: {error}"),
                    })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl Default for ConntrackCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 逐 CPU 统计聚合结果
#[derive(Debug, Default, PartialEq, Eq)]
struct ConntrackStats {
    found: u64,
    invalid: u64,
    ignore: u64,
    insert: u64,
    insert_failed: u64,
    drop: u64,
    early_drop: u64,
    search_restart: u64,
}

/// 十六进制解析（对齐 procfs parseHexUint）
fn parse_hex(field: &str) -> Result<u64, CollectorError> {
    u64::from_str_radix(field, 16).map_err(|error| CollectorError::Parse {
        file: STAT_FILE,
        reason: format!("{field:?} 非十六进制值: {error}"),
    })
}

/// 解析逐 CPU 统计并聚合：表头行（首列 entries）跳过，
/// 列数不足 17 的行跳过（宽容处理老内核变体）
fn parse_conntrack_stat(text: &str) -> Result<ConntrackStats, CollectorError> {
    let mut stats = ConntrackStats::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 17 || fields[0] == "entries" {
            continue;
        }
        stats.found += parse_hex(fields[2])?;
        stats.invalid += parse_hex(fields[4])?;
        stats.ignore += parse_hex(fields[5])?;
        stats.insert += parse_hex(fields[8])?;
        stats.insert_failed += parse_hex(fields[9])?;
        stats.drop += parse_hex(fields[10])?;
        stats.early_drop += parse_hex(fields[11])?;
        stats.search_restart += parse_hex(fields[16])?;
    }
    Ok(stats)
}

impl Collector for ConntrackCollector {
    fn name(&self) -> &'static str {
        "conntrack"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let Some(current) = self.read_u64_file(COUNT_FILE)? else {
            return Err(CollectorError::NoData);
        };
        let Some(limit) = self.read_u64_file(MAX_FILE)? else {
            return Err(CollectorError::NoData);
        };
        let stats = match std::fs::read_to_string(self.proc_path.join(STAT_FILE)) {
            Ok(text) => parse_conntrack_stat(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };

        let mut out = Vec::with_capacity(10);
        let mut entries = MetricFamily::new(
            "node_nf_conntrack_entries",
            "Number of currently allocated flow entries for connection tracking.",
            MetricType::Gauge,
        );
        entries.push(current as f64);
        out.push(entries);

        let mut entries_limit = MetricFamily::new(
            "node_nf_conntrack_entries_limit",
            "Maximum size of connection tracking table.",
            MetricType::Gauge,
        );
        entries_limit.push(limit as f64);
        out.push(entries_limit);

        let stat_family = |name: &'static str, help: &'static str, value: u64| {
            let mut family = MetricFamily::new(name, help, MetricType::Gauge);
            family.push(value as f64);
            family
        };
        out.push(stat_family(
            "node_nf_conntrack_stat_found",
            "Number of searched entries which were successful.",
            stats.found,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_invalid",
            "Number of packets seen which can not be tracked.",
            stats.invalid,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_ignore",
            "Number of packets seen which are already connected to a conntrack entry.",
            stats.ignore,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_insert",
            "Number of entries inserted into the list.",
            stats.insert,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_insert_failed",
            "Number of entries for which list insertion was attempted but failed.",
            stats.insert_failed,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_drop",
            "Number of packets dropped due to conntrack failure.",
            stats.drop,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_early_drop",
            "Number of dropped conntrack entries to make room for new ones, if maximum table size was reached.",
            stats.early_drop,
        ));
        out.push(stat_family(
            "node_nf_conntrack_stat_search_restart",
            "Number of conntrack table lookups which had to be restarted due to hashtable resizes.",
            stats.search_restart,
        ));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = ConntrackCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 10);
        assert_eq!(families[0].name, "node_nf_conntrack_entries");
        assert_eq!(families[0].samples[0].value, 123.0);
        assert_eq!(families[1].name, "node_nf_conntrack_entries_limit");
        assert_eq!(families[1].samples[0].value, 65536.0);

        // 四行 CPU 计数聚合：invalid = 3+2+1+0x2f(47) = 53；
        // ignore = 0x588a+0x56a4+0x58d4+0x5688 = 89738；search_restart = 0+2+1+4 = 7
        let value = |name: &str| -> f64 {
            families
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("缺少指标 {name}"))
                .samples[0]
                .value
        };
        assert_eq!(value("node_nf_conntrack_stat_found"), 0.0);
        assert_eq!(value("node_nf_conntrack_stat_invalid"), 53.0);
        assert_eq!(value("node_nf_conntrack_stat_ignore"), 89_738.0);
        assert_eq!(value("node_nf_conntrack_stat_insert"), 0.0);
        assert_eq!(value("node_nf_conntrack_stat_drop"), 0.0);
        assert_eq!(value("node_nf_conntrack_stat_early_drop"), 0.0);
        assert_eq!(value("node_nf_conntrack_stat_search_restart"), 7.0);
    }

    #[test]
    fn test_parse_skips_header_and_short_lines() {
        let stats = parse_conntrack_stat(
            "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart\n00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004\n残缺行\n",
        )
        .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.search_restart, 4);
        assert_eq!(stats.invalid, 0);
    }

    #[test]
    fn test_parse_rejects_bad_hex() {
        assert!(matches!(
            parse_conntrack_stat(
                "00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 zz000000"
            ),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_files_is_nodata() {
        let collector = ConntrackCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
