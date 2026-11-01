//! softnet 采集器：软中断网络处理统计。
//!
//! 对齐 node_exporter `softnet_linux.go`（默认启用）：解析
//! /proc/net/softnet_stat 逐 CPU 的十六进制计数行，输出（标签 cpu，
//! CPU 序号为 0 起的行序号，对齐 procfs）：
//! - `node_softnet_processed_total` / `_dropped_total` / `_times_squeezed_total`
//!
//!   / `_cpu_collision_total` / `_received_rps_total` / `_flow_limit_count_total`
//!   （Counter，列偏移 0/1/2/4/5/10，越界列记 0）；
//! - `node_softnet_backlog_len`（Gauge，列偏移 12，越界记 0）。
//!
//! 文件缺失按 Go 语义报错；字段非十六进制时解析失败。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// softnet 统计文件（相对 proc_path）
const SOFTNET_FILE: &str = "net/softnet_stat";

pub struct SoftnetCollector {
    proc_path: PathBuf,
}

impl SoftnetCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for SoftnetCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个 CPU 的 softnet 统计（越界列保持 0，对齐 procfs 的按位取值）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SoftnetStat {
    processed: u64,
    dropped: u64,
    time_squeeze: u64,
    cpu_collision: u64,
    received_rps: u64,
    flow_limit_count: u64,
    softnet_backlog_len: u64,
}

/// 解析 softnet_stat 文本：每行一组十六进制计数，行序号即 CPU 序号
fn parse_softnet_stat(text: &str) -> Result<Vec<SoftnetStat>, CollectorError> {
    let mut stats = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 列偏移对齐 procfs：0/1/2/4/5/10/12，缺失列记 0
        let value = |index: usize| -> Result<u64, CollectorError> {
            match fields.get(index) {
                Some(field) => {
                    u64::from_str_radix(field, 16).map_err(|error| CollectorError::Parse {
                        file: SOFTNET_FILE,
                        reason: format!("{field:?} 非十六进制值: {error}"),
                    })
                }
                None => Ok(0),
            }
        };
        stats.push(SoftnetStat {
            processed: value(0)?,
            dropped: value(1)?,
            time_squeeze: value(2)?,
            cpu_collision: value(4)?,
            received_rps: value(5)?,
            flow_limit_count: value(10)?,
            softnet_backlog_len: value(12)?,
        });
    }
    Ok(stats)
}

impl Collector for SoftnetCollector {
    fn name(&self) -> &'static str {
        "softnet"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(SOFTNET_FILE))?;
        let stats = parse_softnet_stat(&text)?;
        // 空文件无样本输出，族保持为空（对齐 Go：空统计不报错）

        let mut out = Vec::with_capacity(7);
        let counter = |name: &'static str, help: &'static str| {
            MetricFamily::new(name, help, MetricType::Counter)
        };
        let mut processed = counter(
            "node_softnet_processed_total",
            "Number of processed packets",
        );
        let mut dropped = counter("node_softnet_dropped_total", "Number of dropped packets");
        let mut time_squeeze = counter(
            "node_softnet_times_squeezed_total",
            "Number of times processing packets ran out of quota",
        );
        let mut cpu_collision = counter(
            "node_softnet_cpu_collision_total",
            "Number of collision occur while obtaining device lock while transmitting",
        );
        let mut received_rps = counter(
            "node_softnet_received_rps_total",
            "Number of times cpu woken up received_rps",
        );
        let mut flow_limit = counter(
            "node_softnet_flow_limit_count_total",
            "Number of times flow limit has been reached",
        );
        let mut backlog = MetricFamily::new(
            "node_softnet_backlog_len",
            "Softnet backlog status",
            MetricType::Gauge,
        );
        for (index, stat) in stats.iter().enumerate() {
            let cpu = index.to_string();
            processed.push_labeled(cpu_labeled(&cpu), stat.processed as f64);
            dropped.push_labeled(cpu_labeled(&cpu), stat.dropped as f64);
            time_squeeze.push_labeled(cpu_labeled(&cpu), stat.time_squeeze as f64);
            cpu_collision.push_labeled(cpu_labeled(&cpu), stat.cpu_collision as f64);
            received_rps.push_labeled(cpu_labeled(&cpu), stat.received_rps as f64);
            flow_limit.push_labeled(cpu_labeled(&cpu), stat.flow_limit_count as f64);
            backlog.push_labeled(cpu_labeled(&cpu), stat.softnet_backlog_len as f64);
        }
        out.extend([
            processed,
            dropped,
            time_squeeze,
            cpu_collision,
            received_rps,
            flow_limit,
            backlog,
        ]);
        Ok(out)
    }
}

/// cpu 标签对
fn cpu_labeled(cpu: &str) -> Vec<(String, String)> {
    vec![("cpu".to_string(), cpu.to_string())]
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
        let collector = SoftnetCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 7);
        assert_eq!(families[0].name, "node_softnet_processed_total");
        assert_eq!(families[0].mtype, MetricType::Counter);
        // fixture 4 行 × 11 列：cpu0 processed=0x49279，cpu1 dropped=0x29=41
        assert_eq!(families[0].samples[0].value, 299_641.0);
        assert_eq!(families[0].samples[0].labels[0].1, "0");
        assert_eq!(families[1].samples[1].value, 41.0);
        // time_squeeze：cpu0 第 3 列 = 1
        assert_eq!(families[2].samples[0].value, 1.0);
        // backlog_len 需要 13 列，fixture 11 列 → 全 0
        assert!(families[6].samples.iter().all(|s| s.value == 0.0));
    }

    #[test]
    fn test_parse_backlog_and_flow_limit() {
        // 13 列以上的行：[10]=flow_limit、[12]=backlog_len
        let stats = parse_softnet_stat(
            "0000000a 0000000b 0000000c 00000000 0000000d 0000000e 00000000 00000000 00000000 00000000 0000000f 00000000 00000011\n",
        )
        .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].processed, 0xa);
        assert_eq!(stats[0].dropped, 0xb);
        assert_eq!(stats[0].time_squeeze, 0xc);
        assert_eq!(stats[0].cpu_collision, 0xd);
        assert_eq!(stats[0].received_rps, 0xe);
        assert_eq!(stats[0].flow_limit_count, 0xf);
        assert_eq!(stats[0].softnet_backlog_len, 0x11);
    }

    #[test]
    fn test_parse_rejects_bad_hex() {
        assert!(matches!(
            parse_softnet_stat(
                "not-hex 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
            ),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = SoftnetCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
