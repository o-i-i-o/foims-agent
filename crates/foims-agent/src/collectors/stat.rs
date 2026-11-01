//! stat 采集器：/proc/stat 内核计数。
//!
//! 对齐 node_exporter `stat_linux.go`（默认启用）：输出
//! - `node_intr_total`（Counter，intr 行首个计数）；
//! - `node_context_switches_total`（Counter，ctxt）；
//! - `node_forks_total`（Counter，processes）；
//! - `node_procs_running` / `node_procs_blocked`（Gauge）。
//!
//! 偏离：`node_boot_time_seconds` 由 boottime 采集器负责输出（避免重复族）；
//! `--collector.stat.softirq` 的 per-vector 指标默认关闭，未移植。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// /proc/stat 文件（相对 proc_path）
const STAT_FILE: &str = "stat";

pub struct StatCollector {
    proc_path: PathBuf,
}

impl StatCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for StatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// /proc/stat 关键计数字段
#[derive(Debug, Default, PartialEq, Eq)]
struct KernelStat {
    intr_total: Option<u64>,
    context_switches: Option<u64>,
    process_created: Option<u64>,
    processes_running: Option<u64>,
    processes_blocked: Option<u64>,
}

/// 解析 /proc/stat：提取 intr 首值、ctxt、processes、procs_running、procs_blocked
fn parse_kernel_stat(text: &str) -> Result<KernelStat, CollectorError> {
    let mut stat = KernelStat::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        let parse_value = |field: Option<&str>| -> Option<u64> {
            field.and_then(|value| value.parse::<u64>().ok())
        };
        match key {
            "intr" => stat.intr_total = parse_value(fields.next()),
            "ctxt" => stat.context_switches = parse_value(fields.next()),
            "processes" => stat.process_created = parse_value(fields.next()),
            "procs_running" => stat.processes_running = parse_value(fields.next()),
            "procs_blocked" => stat.processes_blocked = parse_value(fields.next()),
            _ => {}
        }
    }
    // 必需字段缺失时对齐 procfs Stat() 报无效数据错误
    if stat.intr_total.is_none()
        || stat.context_switches.is_none()
        || stat.process_created.is_none()
        || stat.processes_running.is_none()
        || stat.processes_blocked.is_none()
    {
        return Err(CollectorError::Parse {
            file: STAT_FILE,
            reason: "缺少必需字段（intr/ctxt/processes/procs_running/procs_blocked）".to_string(),
        });
    }
    Ok(stat)
}

impl Collector for StatCollector {
    fn name(&self) -> &'static str {
        "stat"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(STAT_FILE))?;
        let stat = parse_kernel_stat(&text)?;

        let mut intr = MetricFamily::new(
            "node_intr_total",
            "Total number of interrupts serviced.",
            MetricType::Counter,
        );
        intr.push(stat.intr_total.unwrap_or(0) as f64);

        let mut ctxt = MetricFamily::new(
            "node_context_switches_total",
            "Total number of context switches.",
            MetricType::Counter,
        );
        ctxt.push(stat.context_switches.unwrap_or(0) as f64);

        let mut forks = MetricFamily::new(
            "node_forks_total",
            "Total number of forks.",
            MetricType::Counter,
        );
        forks.push(stat.process_created.unwrap_or(0) as f64);

        let mut procs_running = MetricFamily::new(
            "node_procs_running",
            "Number of processes in runnable state.",
            MetricType::Gauge,
        );
        procs_running.push(stat.processes_running.unwrap_or(0) as f64);

        let mut procs_blocked = MetricFamily::new(
            "node_procs_blocked",
            "Number of processes blocked waiting for I/O to complete.",
            MetricType::Gauge,
        );
        procs_blocked.push(stat.processes_blocked.unwrap_or(0) as f64);

        Ok(vec![intr, ctxt, forks, procs_running, procs_blocked])
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
        let collector = StatCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 5);
        assert_eq!(families[0].name, "node_intr_total");
        assert_eq!(families[0].mtype, MetricType::Counter);
        assert_eq!(families[0].samples[0].value, 8_885_917.0);
        assert_eq!(families[1].name, "node_context_switches_total");
        assert_eq!(families[1].samples[0].value, 38_014_093.0);
        assert_eq!(families[2].name, "node_forks_total");
        assert_eq!(families[2].samples[0].value, 26_442.0);
        assert_eq!(families[3].name, "node_procs_running");
        assert_eq!(families[3].mtype, MetricType::Gauge);
        assert_eq!(families[3].samples[0].value, 2.0);
        assert_eq!(families[4].name, "node_procs_blocked");
        assert_eq!(families[4].samples[0].value, 0.0);
    }

    #[test]
    fn test_parse_requires_mandatory_fields() {
        // 缺 procs_blocked → 无效数据
        assert!(matches!(
            parse_kernel_stat("intr 100\nctxt 200\nprocesses 300\nprocs_running 1\n"),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = StatCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
