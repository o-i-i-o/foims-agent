//! pressure 采集器：PSI 压力失速信息。
//!
//! 对齐 node_exporter `pressure_linux.go`（默认启用）：读取 /proc/pressure/
//! {cpu,io,memory,irq}，输出（Counter，微秒值换算为秒）：
//! - `node_pressure_cpu_waiting_seconds_total`（cpu 的 some.total）；
//! - `node_pressure_io_waiting_seconds_total`（io 的 some.total）、
//!
//!   `node_pressure_io_stalled_seconds_total`（io 的 full.total）；
//! - `node_pressure_memory_waiting_seconds_total` / `_memory_stalled_seconds_total`；
//! - `node_pressure_irq_stalled_seconds_total`（irq 仅有 full 行）。
//!
//! 语义对齐 Go 源：cpu 必须有 some 行，io/memory 必须同时有 some 与 full 行，
//! irq 必须有 full 行，缺失即返回 NoData；全部资源文件缺失同样返回 NoData。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// PSI 目录（相对 proc_path）
const PRESSURE_DIR: &str = "pressure";

/// PSI 资源（对齐 Go psiResources 顺序）
const PSI_RESOURCES: [&str; 4] = ["cpu", "io", "memory", "irq"];

pub struct PressureStatsCollector {
    proc_path: PathBuf,
}

impl PressureStatsCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for PressureStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个资源的 PSI 统计（total 字段，微秒）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PsiStats {
    some: Option<u64>,
    full: Option<u64>,
}

/// 解析 PSI 文本：`some avg10=… total=N` / `full avg10=… total=N` 行，
/// 提取各行的 total（微秒）
fn parse_psi_stats(text: &str) -> Result<PsiStats, CollectorError> {
    let mut stats = PsiStats::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next() else {
            continue;
        };
        let total = fields
            .find_map(|field| field.strip_prefix("total="))
            .ok_or_else(|| CollectorError::Parse {
                file: PRESSURE_DIR,
                reason: format!("缺少 total 字段: {line}"),
            })?
            .parse::<u64>()
            .map_err(|error| CollectorError::Parse {
                file: PRESSURE_DIR,
                reason: format!("total 值非法: {error}"),
            })?;
        match kind {
            "some" => stats.some = Some(total),
            "full" => stats.full = Some(total),
            _ => {}
        }
    }
    Ok(stats)
}

impl Collector for PressureStatsCollector {
    fn name(&self) -> &'static str {
        "pressure"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut out: Vec<MetricFamily> = Vec::new();
        // 记录待推送样本，最后统一构族，保持 Go 的输出顺序
        let mut cpu_waiting: Option<f64> = None;
        let mut io_waiting: Option<f64> = None;
        let mut io_stalled: Option<f64> = None;
        let mut mem_waiting: Option<f64> = None;
        let mut mem_stalled: Option<f64> = None;
        let mut irq_stalled: Option<f64> = None;
        let mut found_resources = 0usize;

        for resource in PSI_RESOURCES {
            let text =
                match std::fs::read_to_string(self.proc_path.join(PRESSURE_DIR).join(resource)) {
                    // 文件缺失：内核 < 4.20 或未启用 CONFIG_PSI，跳过该资源
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                    Ok(text) => text,
                };
            let stats = parse_psi_stats(&text)?;
            let micros = |total: Option<u64>| total.map(|value| value as f64 / 1_000_000.0);
            // 行缺失语义对齐 Go：cpu 缺 some、io/memory 缺 some 或 full、
            // irq 缺 full 均视为无有效 PSI 数据
            let complete = match resource {
                "cpu" => {
                    cpu_waiting = micros(stats.some);
                    cpu_waiting.is_some()
                }
                "io" => {
                    io_waiting = micros(stats.some);
                    io_stalled = micros(stats.full);
                    io_waiting.is_some() && io_stalled.is_some()
                }
                "memory" => {
                    mem_waiting = micros(stats.some);
                    mem_stalled = micros(stats.full);
                    mem_waiting.is_some() && mem_stalled.is_some()
                }
                "irq" => {
                    irq_stalled = micros(stats.full);
                    irq_stalled.is_some()
                }
                _ => false,
            };
            if !complete {
                return Err(CollectorError::NoData);
            }
            found_resources += 1;
        }
        if found_resources == 0 {
            return Err(CollectorError::NoData);
        }

        let family = |name: &'static str, help: &'static str, value: Option<f64>| {
            let mut f = MetricFamily::new(name, help, MetricType::Counter);
            if let Some(value) = value {
                f.push(value);
            }
            f
        };
        out.push(family(
            "node_pressure_cpu_waiting_seconds_total",
            "Total time in seconds that processes have waited for CPU time",
            cpu_waiting,
        ));
        out.push(family(
            "node_pressure_io_waiting_seconds_total",
            "Total time in seconds that processes have waited due to IO congestion",
            io_waiting,
        ));
        out.push(family(
            "node_pressure_io_stalled_seconds_total",
            "Total time in seconds no process could make progress due to IO congestion",
            io_stalled,
        ));
        out.push(family(
            "node_pressure_memory_waiting_seconds_total",
            "Total time in seconds that processes have waited for memory",
            mem_waiting,
        ));
        out.push(family(
            "node_pressure_memory_stalled_seconds_total",
            "Total time in seconds no process could make progress due to memory congestion",
            mem_stalled,
        ));
        out.push(family(
            "node_pressure_irq_stalled_seconds_total",
            "Total time in seconds no process could make progress due to IRQ congestion",
            irq_stalled,
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
        let collector = PressureStatsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 6);
        let value = |name: &str| -> f64 {
            families
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("缺少指标 {name}"))
                .samples[0]
                .value
        };
        // 微秒 → 秒
        assert_eq!(
            value("node_pressure_cpu_waiting_seconds_total"),
            14_036_781f64 / 1_000_000.0
        );
        assert_eq!(
            value("node_pressure_io_waiting_seconds_total"),
            159_886_802f64 / 1_000_000.0
        );
        assert_eq!(
            value("node_pressure_io_stalled_seconds_total"),
            159_229_614f64 / 1_000_000.0
        );
        assert_eq!(value("node_pressure_memory_waiting_seconds_total"), 0.0);
        assert_eq!(value("node_pressure_memory_stalled_seconds_total"), 0.0);
        assert_eq!(
            value("node_pressure_irq_stalled_seconds_total"),
            8_494f64 / 1_000_000.0
        );
    }

    #[test]
    fn test_parse_psi_stats() {
        let stats =
            parse_psi_stats("some avg10=0.18 avg60=0.34 avg300=0.10 total=159886802\nfull avg10=0.18 avg60=0.34 avg300=0.10 total=159229614\n")
                .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.some, Some(159_886_802));
        assert_eq!(stats.full, Some(159_229_614));
        // 缺 total 字段报解析错误
        assert!(matches!(
            parse_psi_stats("some avg10=0.00 avg60=0.00"),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_all_resources_is_nodata() {
        let collector = PressureStatsCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
