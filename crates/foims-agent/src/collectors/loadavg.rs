//! loadavg 采集器：系统负载。
//!
//! 对齐 node_exporter `loadavg.go` + `loadavg_linux.go`（Linux 上仅输出三个负载值；
//! node_procs_* 指标由 stat 采集器负责）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const LOADAVG_FILE: &str = "loadavg";

pub struct LoadavgCollector {
    proc_path: PathBuf,
}

impl LoadavgCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for LoadavgCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// /proc/loadavg 一行中的 1m/5m/15m 负载
#[derive(Debug)]
struct Loads {
    one: f64,
    five: f64,
    fifteen: f64,
}

/// 解析 /proc/loadavg（逗号小数点兼容旧内核/locale 变体）
fn parse_loadavg(text: &str) -> Result<Loads, CollectorError> {
    let first = text.lines().next().ok_or(CollectorError::NoData)?.trim();
    let fields: Vec<&str> = first.split_whitespace().collect();
    if fields.len() < 3 {
        return Err(CollectorError::Parse {
            file: LOADAVG_FILE,
            reason: format!("字段数不足: {first}"),
        });
    }
    let parse = |field: &str| -> Result<f64, CollectorError> {
        field
            .replace(',', ".")
            .parse::<f64>()
            .map_err(|error| CollectorError::Parse {
                file: LOADAVG_FILE,
                reason: format!("负载值非法: {error}"),
            })
    };
    Ok(Loads {
        one: parse(fields[0])?,
        five: parse(fields[1])?,
        fifteen: parse(fields[2])?,
    })
}

impl Collector for LoadavgCollector {
    fn name(&self) -> &'static str {
        "loadavg"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(LOADAVG_FILE))?;
        let loads = parse_loadavg(&text)?;

        let mut load1 = MetricFamily::new("node_load1", "1m load average.", MetricType::Gauge);
        let mut load5 = MetricFamily::new("node_load5", "5m load average.", MetricType::Gauge);
        let mut load15 = MetricFamily::new("node_load15", "15m load average.", MetricType::Gauge);
        load1.push(loads.one);
        load5.push(loads.five);
        load15.push(loads.fifteen);

        Ok(vec![load1, load5, load15])
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
        let collector = LoadavgCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 3);
        assert_eq!(families[0].name, "node_load1");
        assert_eq!(families[0].samples[0].value, 0.21);
        assert_eq!(families[1].name, "node_load5");
        assert_eq!(families[2].name, "node_load15");
    }

    #[test]
    fn test_parse_rejects_short_content() {
        assert!(matches!(
            parse_loadavg("0.1 0.2"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(parse_loadavg(""), Err(CollectorError::NoData)));
    }
}
