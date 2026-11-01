//! boottime 采集器：系统启动时间。
//!
//! 对齐 node_exporter `boot_time_*.go`（`registerCollector("boottime",
//! defaultEnabled)`，默认启用）。Linux 上原版没有独立的 boottime 采集器，
//! `node_boot_time_seconds` 由 stat 采集器从 /proc/stat 的 btime 行输出
//! （stat_linux.go + procfs `Stat.BootTime`）；本移植按原指标语义独立成
//! boottime 采集器，指标名/help/Gauge 类型逐字对齐 stat_linux.go。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const STAT_FILE: &str = "stat";

pub struct BootTimeCollector {
    proc_path: PathBuf,
}

impl BootTimeCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for BootTimeCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 /proc/stat 文本提取 btime（系统启动时间，Unix 秒；
/// 对齐 procfs 对 btime 行按无符号整数解析的语义）
fn parse_btime(text: &str) -> Result<f64, CollectorError> {
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("btime") {
            continue;
        }
        let Some(value) = fields.next() else {
            return Err(CollectorError::Parse {
                file: STAT_FILE,
                reason: "btime 行缺少值".to_string(),
            });
        };
        let seconds: u64 = value.parse().map_err(|error| CollectorError::Parse {
            file: STAT_FILE,
            reason: format!("btime 值非法: {error}"),
        })?;
        return Ok(seconds as f64);
    }
    Err(CollectorError::NoData)
}

impl Collector for BootTimeCollector {
    fn name(&self) -> &'static str {
        "boottime"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(STAT_FILE))?;
        let btime = parse_btime(&text)?;

        let mut family = MetricFamily::new(
            "node_boot_time_seconds",
            "Node boot time, in unixtime.",
            MetricType::Gauge,
        );
        family.push(btime);
        Ok(vec![family])
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
        let collector = BootTimeCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_boot_time_seconds");
        assert_eq!(families[0].mtype, MetricType::Gauge);
        // fixture /proc/stat 中 btime 行的值
        assert_eq!(families[0].samples[0].value, 1_418_183_276.0);
    }

    #[test]
    fn test_parse_btime() {
        let text = "cpu  1 2 3 4\nctxt 100\nbtime 1700000000\nprocs_running 1\n";
        assert_eq!(
            parse_btime(text).unwrap_or_else(|e| panic!("解析失败: {e}")),
            1_700_000_000.0
        );
        assert!(matches!(
            parse_btime("cpu 1 2 3\nctxt 100\n"),
            Err(CollectorError::NoData)
        ));
        assert!(matches!(
            parse_btime("btime not-a-number\n"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            parse_btime("btime\n"),
            Err(CollectorError::Parse { .. })
        ));
    }
}
