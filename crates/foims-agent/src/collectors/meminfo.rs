//! meminfo 采集器：内存统计。
//!
//! 对齐 node_exporter `meminfo_linux.go`：/proc/meminfo 每个字段映射为
//! `node_memory_<SanitizedKey>_<unit后缀>`；kB 单位换算为字节并追加 `_bytes`，
//! 无单位字段（如 HugePages_Total）不加后缀。字段缺失时对应指标不输出。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const MEMINFO_FILE: &str = "meminfo";

pub struct MeminfoCollector {
    proc_path: PathBuf,
}

impl MeminfoCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for MeminfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 键名净化：非字母数字字符替换为下划线，并去掉首尾多余下划线
/// （对齐 procfs 字段命名：`Active(anon)` → `Active_anon`，`Committed_AS` 保持）
fn sanitize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    // 压缩连续下划线
    let mut result = String::with_capacity(trimmed.len());
    let mut previous_underscore = false;
    for c in trimmed.chars() {
        if c == '_' {
            if !previous_underscore {
                result.push(c);
            }
            previous_underscore = true;
        } else {
            result.push(c);
            previous_underscore = false;
        }
    }
    result
}

impl Collector for MeminfoCollector {
    fn name(&self) -> &'static str {
        "meminfo"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(MEMINFO_FILE))?;
        // 每个字段一个独立指标族（原版 procfs 字段表逐项输出 node_memory_<Key>）
        let mut metrics: Vec<(String, f64)> = Vec::new();
        for line in text.lines() {
            let Some((key_part, value_part)) = line.split_once(':') else {
                continue;
            };
            let key = sanitize_key(key_part.trim());
            if key.is_empty() {
                continue;
            }
            let mut tokens = value_part.split_whitespace();
            let Some(raw_value) = tokens.next() else {
                continue;
            };
            let unit = tokens.next();
            let value: f64 = raw_value.parse().map_err(|error| CollectorError::Parse {
                file: MEMINFO_FILE,
                reason: format!("字段 {key} 值非法: {error}"),
            })?;
            match unit {
                // kB → 字节（/proc/meminfo 的 kB 实为 KiB）
                Some("kB") => metrics.push((format!("{key}_bytes"), value * 1024.0)),
                // 无单位字段（HugePages_Total 等）保持原值、无后缀
                _ => metrics.push((key, value)),
            }
        }
        if metrics.is_empty() {
            return Err(CollectorError::NoData);
        }

        let mut out = Vec::with_capacity(metrics.len());
        for (metric_name, value) in metrics {
            // 对齐 meminfo.go：key 以 _total 结尾计 Counter，其余 Gauge；
            // help 固定为 "Memory information field <key>."
            let mtype = if metric_name.ends_with("_total") {
                MetricType::Counter
            } else {
                MetricType::Gauge
            };
            let mut family = MetricFamily::new(
                &format!("node_memory_{metric_name}"),
                &format!("Memory information field {metric_name}."),
                mtype,
            );
            family.push(value);
            out.push(family);
        }
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
        let collector = MeminfoCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let names: Vec<&str> = families.iter().map(|f| f.name.as_str()).collect();

        // kB 单位换算与后缀
        let total = families
            .iter()
            .find(|f| f.name == "node_memory_MemTotal_bytes")
            .unwrap_or_else(|| panic!("缺少 node_memory_MemTotal_bytes"));
        assert_eq!(total.samples[0].value, 3_742_148.0 * 1024.0);

        // 无单位字段无后缀
        assert!(names.contains(&"node_memory_HugePages_Total"));

        // 括号键名净化
        assert!(names.contains(&"node_memory_Active_anon_bytes"));
        assert!(names.contains(&"node_memory_Committed_AS_bytes"));
    }

    #[test]
    fn test_sanitize_key() {
        assert_eq!(sanitize_key("Active(anon)"), "Active_anon");
        assert_eq!(sanitize_key("Committed_AS"), "Committed_AS");
        assert_eq!(sanitize_key("MemTotal"), "MemTotal");
    }
}
