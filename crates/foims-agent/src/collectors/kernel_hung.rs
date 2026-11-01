//! kernel_hung 采集器：内核 hung task 检测计数。
//!
//! 对齐 node_exporter `kernel_hung_linux.go`（默认启用）：读取
//! /proc/sys/kernel/hung_task_detect_count，输出 `node_kernel_hung_tasks_total`
//! （Counter）。文件缺失（CONFIG_DETECT_HUNG_TASK 未启用）时返回 NoData。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// hung task 计数文件（相对 proc_path）
const HUNG_TASK_FILE: &str = "sys/kernel/hung_task_detect_count";

pub struct KernelHungCollector {
    proc_path: PathBuf,
}

impl KernelHungCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for KernelHungCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for KernelHungCollector {
    fn name(&self) -> &'static str {
        "kernel_hung"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = match std::fs::read_to_string(self.proc_path.join(HUNG_TASK_FILE)) {
            // 文件缺失对齐 Go：hung_task_detect_count 不存在时报 NoData
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
            Ok(text) => text,
        };
        let count = text
            .trim()
            .parse::<u64>()
            .map_err(|error| CollectorError::Parse {
                file: HUNG_TASK_FILE,
                reason: format!("计数值非法: {error}"),
            })?;

        let mut family = MetricFamily::new(
            "node_kernel_hung_tasks_total",
            "Total number of tasks that have been detected as hung since the system booted.",
            MetricType::Counter,
        );
        family.push(count as f64);
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
        let collector = KernelHungCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_kernel_hung_tasks_total");
        assert_eq!(families[0].mtype, MetricType::Counter);
        assert_eq!(families[0].samples[0].value, 42.0);
    }

    #[test]
    fn test_missing_file_is_nodata() {
        let collector = KernelHungCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
