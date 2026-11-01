//! schedstat 采集器：CPU 调度统计。
//!
//! 对齐 node_exporter `schedstat_linux.go`（默认启用）：读取 /proc/schedstat，
//! 输出（Counter，标签 cpu）：
//! - `node_schedstat_running_seconds_total`（运行时长，纳秒换算秒）；
//! - `node_schedstat_waiting_seconds_total`（等待运行时长）；
//! - `node_schedstat_timeslices_total`（时间片数）。
//!
//! 兼容两种 cpu 行格式（对齐 procfs）：内核 6.2+ 的 9 字段版本取
//! 第 7/8/9 列，旧版 4 字段版本取第 2/3/4 列；version/timestamp/domain
//! 行跳过。文件缺失返回 NoData。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 调度统计文件（相对 proc_path）
const SCHEDSTAT_FILE: &str = "schedstat";

/// 纳秒 → 秒
const NS_PER_SEC: f64 = 1e9;

pub struct SchedstatCollector {
    proc_path: PathBuf,
}

impl SchedstatCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for SchedstatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个 CPU 的调度统计（标签 cpu 为 cpuN 的 N）
#[derive(Debug, Clone, PartialEq)]
struct CpuSchedstat {
    cpu: String,
    running_seconds: f64,
    waiting_seconds: f64,
    timeslices: f64,
}

/// 解析 schedstat 文本；非 cpu 行与字段数不符合已知格式的行跳过
fn parse_schedstat(text: &str) -> Result<Vec<CpuSchedstat>, CollectorError> {
    let mut cpus = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(name) = fields.first() else {
            continue;
        };
        let Some(cpu) = name.strip_prefix("cpu") else {
            // version/timestamp/domain 行跳过
            continue;
        };
        if cpu.is_empty() {
            continue;
        }
        // 新版（内核 6.2+）10 字段：运行/等待/时间片在第 8/9/10 列；
        // 旧版 4 字段：在第 2/3/4 列
        let (running_ns, waiting_ns, timeslices) = match fields.len() {
            10 => (fields[7], fields[8], fields[9]),
            4 => (fields[1], fields[2], fields[3]),
            _ => continue,
        };
        let parse_ns = |field: &str| -> Result<u64, CollectorError> {
            field.parse::<u64>().map_err(|error| CollectorError::Parse {
                file: SCHEDSTAT_FILE,
                reason: format!("纳秒值 {field:?} 非法: {error}"),
            })
        };
        let parse_count = |field: &str| -> Result<u64, CollectorError> {
            field.parse::<u64>().map_err(|error| CollectorError::Parse {
                file: SCHEDSTAT_FILE,
                reason: format!("计数值 {field:?} 非法: {error}"),
            })
        };
        cpus.push(CpuSchedstat {
            cpu: cpu.to_string(),
            running_seconds: parse_ns(running_ns)? as f64 / NS_PER_SEC,
            waiting_seconds: parse_ns(waiting_ns)? as f64 / NS_PER_SEC,
            timeslices: parse_count(timeslices)? as f64,
        });
    }
    Ok(cpus)
}

impl Collector for SchedstatCollector {
    fn name(&self) -> &'static str {
        "schedstat"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = match std::fs::read_to_string(self.proc_path.join(SCHEDSTAT_FILE)) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };
        let cpus = parse_schedstat(&text)?;

        let cpu_label = |stat: &CpuSchedstat| vec![("cpu".to_string(), stat.cpu.clone())];
        let mut running = MetricFamily::new(
            "node_schedstat_running_seconds_total",
            "Number of seconds CPU spent running a process.",
            MetricType::Counter,
        );
        let mut waiting = MetricFamily::new(
            "node_schedstat_waiting_seconds_total",
            "Number of seconds spent by processing waiting for this CPU.",
            MetricType::Counter,
        );
        let mut timeslices = MetricFamily::new(
            "node_schedstat_timeslices_total",
            "Number of timeslices executed by CPU.",
            MetricType::Counter,
        );
        for stat in &cpus {
            running.push_labeled(cpu_label(stat), stat.running_seconds);
            waiting.push_labeled(cpu_label(stat), stat.waiting_seconds);
            timeslices.push_labeled(cpu_label(stat), stat.timeslices);
        }
        Ok(vec![running, waiting, timeslices])
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
        let collector = SchedstatCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 3);
        assert_eq!(families[0].name, "node_schedstat_running_seconds_total");
        assert_eq!(families[0].mtype, MetricType::Counter);
        // fixture 为内核 6.2+ 的 9 字段格式：cpu0 运行 2045936778163039 ns
        assert_eq!(families[0].samples.len(), 2);
        assert_eq!(
            families[0].samples[0].value,
            2_045_936_778_163_039f64 / NS_PER_SEC
        );
        assert_eq!(families[0].samples[0].labels[0].1, "0");
        assert_eq!(
            families[0].samples[1].value,
            1_904_686_152_592_476f64 / NS_PER_SEC
        );
        // 等待时长
        assert_eq!(
            families[1].samples[0].value,
            343_796_328_169_361f64 / NS_PER_SEC
        );
        assert_eq!(
            families[1].samples[1].value,
            364_107_263_788_241f64 / NS_PER_SEC
        );
        // 时间片数
        assert_eq!(families[2].samples[0].value, 4_767_485_306.0);
        assert_eq!(families[2].samples[1].value, 5_145_567_945.0);
    }

    #[test]
    fn test_parse_legacy_format() {
        // 旧版 4 字段格式：cpuN <运行> <等待> <时间片>
        let cpus =
            parse_schedstat("version 15\ntimestamp 15819019232\ncpu0 100 200 3\ndomain0 1 2 3 4\n")
                .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(cpus.len(), 1);
        assert_eq!(cpus[0].cpu, "0");
        assert_eq!(cpus[0].running_seconds, 100.0 / NS_PER_SEC);
        assert_eq!(cpus[0].waiting_seconds, 200.0 / NS_PER_SEC);
        assert_eq!(cpus[0].timeslices, 3.0);
    }

    #[test]
    fn test_missing_file_is_nodata() {
        let collector = SchedstatCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
