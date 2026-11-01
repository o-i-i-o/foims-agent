//! vmstat 采集器：/proc/vmstat 虚拟内存统计直通。
//!
//! 对齐 node_exporter `vmstat_linux.go`（默认启用）：逐行解析
//! "字段 值"，输出 `node_vmstat_<字段>`（Untyped，help 为
//! "/proc/vmstat information field <字段>."）。
//! 默认过滤正则 `^(oom_kill|pgpg|pswp|pg.*fault).*` 以字符串前缀逻辑
//! 等价实现（oom_kill/pgpg/pswp 前缀，或 pg 开头且其余部分含 fault），
//! 遵循移植规格不引入 regex 依赖。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// vmstat 文件（相对 proc_path）
const VMSTAT_FILE: &str = "vmstat";

pub struct VmstatCollector {
    proc_path: PathBuf,
}

impl VmstatCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for VmstatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 默认过滤规则（等价于正则 ^(oom_kill|pgpg|pswp|pg.*fault).*）
fn field_selected(field: &str) -> bool {
    field.starts_with("oom_kill")
        || field.starts_with("pgpg")
        || field.starts_with("pswp")
        || (field.starts_with("pg") && field[2..].contains("fault"))
}

/// 解析 vmstat 文本，返回选中的 (字段, 值) 序列
fn parse_vmstat(text: &str) -> Result<Vec<(String, f64)>, CollectorError> {
    let mut fields = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(value_text) = parts.next() else {
            return Err(CollectorError::Parse {
                file: VMSTAT_FILE,
                reason: format!("行缺少值: {line}"),
            });
        };
        let value = value_text
            .parse::<f64>()
            .map_err(|error| CollectorError::Parse {
                file: VMSTAT_FILE,
                reason: format!("{name} 值非法: {error}"),
            })?;
        if field_selected(name) {
            fields.push((name.to_string(), value));
        }
    }
    Ok(fields)
}

impl Collector for VmstatCollector {
    fn name(&self) -> &'static str {
        "vmstat"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(VMSTAT_FILE))?;
        let fields = parse_vmstat(&text)?;

        let mut out = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            let mut family = MetricFamily::new(
                &format!("node_vmstat_{name}"),
                &format!("/proc/vmstat information field {name}."),
                MetricType::Untyped,
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
        let collector = VmstatCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let value = |name: &str| -> f64 {
            families
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("缺少指标 {name}"))
                .samples[0]
                .value
        };
        // 默认过滤命中的字段（对齐 e2e 期望输出集合）
        assert_eq!(value("node_vmstat_oom_kill"), 0.0);
        assert_eq!(value("node_vmstat_pgpgin"), 7_344_136.0);
        assert_eq!(value("node_vmstat_pgpgout"), 1_541_180_581.0);
        assert_eq!(value("node_vmstat_pswpin"), 1476.0);
        assert_eq!(value("node_vmstat_pswpout"), 35_045.0);
        assert_eq!(value("node_vmstat_pgfault"), 2_320_168_809.0);
        assert_eq!(value("node_vmstat_pgmajfault"), 507_162.0);
        // help 与类型对齐 Go 源
        let family = families
            .iter()
            .find(|f| f.name == "node_vmstat_pgpgin")
            .unwrap_or_else(|| panic!("缺少指标"));
        assert_eq!(family.mtype, MetricType::Untyped);
        assert_eq!(family.help, "/proc/vmstat information field pgpgin.");
        // 未命中过滤的字段不输出
        assert!(
            families
                .iter()
                .all(|f| !f.name.starts_with("node_vmstat_nr_"))
        );
    }

    #[test]
    fn test_field_selected() {
        assert!(field_selected("oom_kill"));
        assert!(field_selected("oom_kill_count"));
        assert!(field_selected("pgpgin"));
        assert!(field_selected("pswpout"));
        assert!(field_selected("pgfault"));
        assert!(field_selected("pgmajfault"));
        assert!(!field_selected("nr_free_pages"));
        assert!(!field_selected("pgrotated"));
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = VmstatCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
