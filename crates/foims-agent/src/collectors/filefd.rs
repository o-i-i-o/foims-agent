//! filefd 采集器：文件描述符统计。
//!
//! 对齐 node_exporter `filefd_linux.go`（默认启用）：读取 /proc/sys/fs/file-nr
//! （单行三个制表符分隔的值），输出：
//! - `node_filefd_allocated`：第 1 列（已分配）；
//! - `node_filefd_maximum`：第 3 列（上限；第 2 列在 Linux 2.6 起恒为 0，跳过）。
//!
//! 文件缺失按 Go 语义报错（success=0）。Go 以 map 迭代输出（顺序随机），
//! 本移植固定 allocated → maximum 顺序。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// file-nr 文件（相对 proc_path）
const FILE_NR: &str = "sys/fs/file-nr";

pub struct FileFdCollector {
    proc_path: PathBuf,
}

impl FileFdCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for FileFdCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析 file-nr 内容：制表符分隔，返回 (allocated, maximum)
fn parse_file_nr(text: &str) -> Result<(f64, f64), CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: "file-nr",
        reason,
    };
    let parts: Vec<&str> = text.trim().split('\t').collect();
    if parts.len() < 3 {
        return Err(invalid(format!("字段数不足（需 3 列）: {text}")));
    }
    let parse = |value: &str| -> Result<f64, CollectorError> {
        value
            .parse::<f64>()
            .map_err(|error| invalid(format!("值 {value:?} 非法: {error}")))
    };
    Ok((parse(parts[0])?, parse(parts[2])?))
}

impl Collector for FileFdCollector {
    fn name(&self) -> &'static str {
        "filefd"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(FILE_NR))?;
        let (allocated, maximum) = parse_file_nr(&text)?;

        let mut allocated_family = MetricFamily::new(
            "node_filefd_allocated",
            "File descriptor statistics: allocated.",
            MetricType::Gauge,
        );
        allocated_family.push(allocated);

        let mut maximum_family = MetricFamily::new(
            "node_filefd_maximum",
            "File descriptor statistics: maximum.",
            MetricType::Gauge,
        );
        maximum_family.push(maximum);

        Ok(vec![allocated_family, maximum_family])
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
        let collector = FileFdCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].name, "node_filefd_allocated");
        assert_eq!(families[0].mtype, MetricType::Gauge);
        assert_eq!(families[0].samples[0].value, 1024.0);
        assert_eq!(families[1].name, "node_filefd_maximum");
        assert_eq!(families[1].samples[0].value, 1_631_329.0);
    }

    #[test]
    fn test_parse_rejects_short_content() {
        assert!(matches!(
            parse_file_nr("1024\t0"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            parse_file_nr("abc\t0\t1"),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = FileFdCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
