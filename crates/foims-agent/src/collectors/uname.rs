//! uname 采集器：内核与系统信息。
//!
//! 对齐 node_exporter `uname.go` + `uname_linux.go`
//! （`registerCollector("uname", defaultEnabled)`，默认启用）。输出单一指标
//! `node_uname_info`（Gauge，值恒为 1），标签 sysname/release/version/machine/
//! nodename/domainname 逐字对齐 Go 源描述符。系统调用经 rustix::system::uname
//! 完成（crate 内零 unsafe）；「Uname → 指标族」抽为纯函数以便合成值测试，
//! collect() 只做系统调用并调用纯函数。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

pub struct UnameCollector;

impl UnameCollector {
    /// 生产构造
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnameCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// uname(2) 返回的系统信息（字段与顺序对齐 Go 源 `uname` 结构体）
#[derive(Debug, Clone, PartialEq, Eq)]
struct Uname {
    sysname: String,
    release: String,
    version: String,
    machine: String,
    nodename: String,
    domainname: String,
}

impl Uname {
    /// 从 rustix 的 uname 结果构造（内核字符串按 NUL 截断，非 UTF-8 字节有损替换）
    fn from_rustix(raw: rustix::system::Uname) -> Self {
        Self {
            sysname: raw.sysname().to_string_lossy().into_owned(),
            release: raw.release().to_string_lossy().into_owned(),
            version: raw.version().to_string_lossy().into_owned(),
            machine: raw.machine().to_string_lossy().into_owned(),
            nodename: raw.nodename().to_string_lossy().into_owned(),
            domainname: raw.domainname().to_string_lossy().into_owned(),
        }
    }
}

/// 纯函数：uname 信息 → 指标族（node_uname_info，Gauge 恒 1，
/// 标签顺序对齐 Go 源 unameDesc）
fn uname_metrics(info: &Uname) -> Vec<MetricFamily> {
    let mut family = MetricFamily::new(
        "node_uname_info",
        "Labeled system information as provided by the uname system call.",
        MetricType::Gauge,
    );
    family.push_labeled(
        vec![
            ("sysname".to_string(), info.sysname.clone()),
            ("release".to_string(), info.release.clone()),
            ("version".to_string(), info.version.clone()),
            ("machine".to_string(), info.machine.clone()),
            ("nodename".to_string(), info.nodename.clone()),
            ("domainname".to_string(), info.domainname.clone()),
        ],
        1.0,
    );
    vec![family]
}

impl Collector for UnameCollector {
    fn name(&self) -> &'static str {
        "uname"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        // uname(2) 无错误路径：rustix 直接返回 Uname 而非 Result
        let raw = rustix::system::uname();
        Ok(uname_metrics(&Uname::from_rustix(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uname_metrics_synthetic() {
        let info = Uname {
            sysname: "Linux".to_string(),
            release: "6.8.0-45-generic".to_string(),
            version: "#45-Ubuntu SMP".to_string(),
            machine: "x86_64".to_string(),
            nodename: "foims-host".to_string(),
            domainname: "(none)".to_string(),
        };
        let families = uname_metrics(&info);
        assert_eq!(families.len(), 1);
        let family = &families[0];
        assert_eq!(family.name, "node_uname_info");
        assert_eq!(family.mtype, MetricType::Gauge);
        assert_eq!(family.samples.len(), 1);
        assert_eq!(family.samples[0].value, 1.0);
        let labels = &family.samples[0].labels;
        assert_eq!(labels.len(), 6);
        assert_eq!(labels[0], ("sysname".to_string(), "Linux".to_string()));
        assert_eq!(
            labels[1],
            ("release".to_string(), "6.8.0-45-generic".to_string())
        );
        assert_eq!(
            labels[2],
            ("version".to_string(), "#45-Ubuntu SMP".to_string())
        );
        assert_eq!(labels[3], ("machine".to_string(), "x86_64".to_string()));
        assert_eq!(
            labels[4],
            ("nodename".to_string(), "foims-host".to_string())
        );
        assert_eq!(labels[5], ("domainname".to_string(), "(none)".to_string()));
    }

    #[test]
    fn test_collect_via_syscall() {
        let collector = UnameCollector::new();
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_uname_info");
        assert_eq!(families[0].samples[0].labels.len(), 6);
        assert_eq!(families[0].samples[0].value, 1.0);
    }
}
