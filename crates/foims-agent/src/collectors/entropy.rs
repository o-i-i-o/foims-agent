//! entropy 采集器：内核熵池。
//!
//! 对齐 node_exporter `entropy_linux.go`（默认启用）：读取
//! /proc/sys/kernel/random/entropy_avail 与 poolsize，输出
//! `node_entropy_available_bits` / `node_entropy_pool_size_bits`（Gauge）。
//! 任一文件缺失时按 Go 语义报错（success=0），而非静默跳过。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// random 统计目录（相对 proc_path）
const RANDOM_DIR: &str = "sys/kernel/random";

pub struct EntropyCollector {
    proc_path: PathBuf,
}

impl EntropyCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }

    /// 读取单个 u64 值文件
    fn read_u64(&self, file: &str) -> Result<u64, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(RANDOM_DIR).join(file))?;
        text.trim()
            .parse::<u64>()
            .map_err(|error| CollectorError::Parse {
                file: RANDOM_DIR,
                reason: format!("{file} 内容非法: {error}"),
            })
    }
}

impl Default for EntropyCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for EntropyCollector {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        // Go 源 entropyAvaliable 缺失即报错（不回退 NoData）
        let available = self.read_u64("entropy_avail")?;
        let pool_size = self.read_u64("poolsize")?;

        let mut avail_family = MetricFamily::new(
            "node_entropy_available_bits",
            "Bits of available entropy.",
            MetricType::Gauge,
        );
        avail_family.push(available as f64);

        let mut pool_family = MetricFamily::new(
            "node_entropy_pool_size_bits",
            "Bits of entropy pool.",
            MetricType::Gauge,
        );
        pool_family.push(pool_size as f64);

        Ok(vec![avail_family, pool_family])
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
        let collector = EntropyCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].name, "node_entropy_available_bits");
        assert_eq!(families[0].mtype, MetricType::Gauge);
        assert_eq!(families[0].samples[0].value, 1337.0);
        assert_eq!(families[1].name, "node_entropy_pool_size_bits");
        assert_eq!(families[1].samples[0].value, 4096.0);
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = EntropyCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        // 对齐 Go：缺失 entropy_avail 报错而非 NoData
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
