//! sockstat 采集器：socket 使用统计。
//!
//! 对齐 node_exporter `sockstat_linux.go`（默认启用）：解析 /proc/net/sockstat
//! 与 /proc/net/sockstat6，输出：
//! - `node_sockstat_sockets_used`（仅 IPv4 文件的 sockets 行）；
//! - `node_sockstat_<协议>_{inuse,orphan,tw,alloc,mem,memory}`（按文件中出现
//!
//!   的键输出，帮助文案统一为 "Number of <协议> sockets in state <键>."）；
//! - `node_sockstat_<协议>_mem_bytes`（mem × 页大小，经 rustix page_size 获取）。
//!
//! 两侧文件均缺失时不报错、无样本（对齐 Go）。

use std::path::PathBuf;

use rustix::param::page_size;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// socket 统计文件（相对 proc_path）
const SOCKSTAT_FILE: &str = "net/sockstat";
const SOCKSTAT6_FILE: &str = "net/sockstat6";

pub struct SockstatCollector {
    proc_path: PathBuf,
}

impl SockstatCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for SockstatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个协议的计数字段（缺失键记 None，不输出对应指标）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProtocolStats {
    in_use: Option<u64>,
    orphan: Option<u64>,
    tw: Option<u64>,
    alloc: Option<u64>,
    mem: Option<u64>,
    memory: Option<u64>,
}

/// 单个 socket 统计文件内容（used 仅 IPv4 文件存在）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct NetSockstat {
    used: Option<u64>,
    protocols: Vec<(String, ProtocolStats)>,
}

/// 解析 socket 统计文本：首行 `sockets: used N`，其余 `<协议>: <键> <值> ...`
fn parse_sockstat(text: &str) -> Result<NetSockstat, CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: SOCKSTAT_FILE,
        reason,
    };
    let mut stat = NetSockstat::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("sockets:") {
            let mut fields = rest.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some("used"), Some(value)) => {
                    let value = value
                        .parse::<u64>()
                        .map_err(|error| invalid(format!("sockets used 值非法: {error}")))?;
                    stat.used = Some(value);
                }
                _ => return Err(invalid("sockets 行缺少 used 值".to_string())),
            }
            continue;
        }
        // 协议行：`TCP: inuse 4 orphan 0 ...`
        let Some((proto, rest)) = line.split_once(':') else {
            return Err(invalid(format!("行缺少协议冒号: {line}")));
        };
        let mut stats = ProtocolStats::default();
        let mut fields = rest.split_whitespace();
        while let Some(key) = fields.next() {
            let Some(value) = fields.next() else {
                return Err(invalid(format!("{proto} 行键 {key} 缺少值")));
            };
            let value = value
                .parse::<u64>()
                .map_err(|error| invalid(format!("{proto} 行键 {key} 值非法: {error}")))?;
            match key {
                "inuse" => stats.in_use = Some(value),
                "orphan" => stats.orphan = Some(value),
                "tw" => stats.tw = Some(value),
                "alloc" => stats.alloc = Some(value),
                "mem" => stats.mem = Some(value),
                "memory" => stats.memory = Some(value),
                // 未知键忽略（对齐 procfs 对新内核新增字段的宽容处理）
                _ => {}
            }
        }
        stat.protocols.push((proto.to_string(), stats));
    }
    Ok(stat)
}

impl Collector for SockstatCollector {
    fn name(&self) -> &'static str {
        "sockstat"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let read_file = |file: &str| -> Result<Option<NetSockstat>, CollectorError> {
            match std::fs::read_to_string(self.proc_path.join(file)) {
                Ok(text) => Ok(Some(parse_sockstat(&text)?)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        };
        let v4 = read_file(SOCKSTAT_FILE)?;
        let v6 = read_file(SOCKSTAT6_FILE)?;

        let mut out: Vec<MetricFamily> = Vec::new();
        let bytes_per_page = page_size() as f64;
        for (is_ipv6, stat) in [(false, v4), (true, v6)] {
            let Some(stat) = stat else {
                continue;
            };
            // sockets_used 仅由 IPv4 文件提供（对齐 Go）
            if !is_ipv6 && let Some(used) = stat.used {
                let mut family = MetricFamily::new(
                    "node_sockstat_sockets_used",
                    "Number of IPv4 sockets in use.",
                    MetricType::Gauge,
                );
                family.push(used as f64);
                out.push(family);
            }
            for (proto, stats) in &stat.protocols {
                let metric = |name: &str, help: String, value: f64| {
                    let mut family = MetricFamily::new(name, &help, MetricType::Gauge);
                    family.push(value);
                    family
                };
                let suffixes = [
                    ("inuse", stats.in_use),
                    ("orphan", stats.orphan),
                    ("tw", stats.tw),
                    ("alloc", stats.alloc),
                    ("mem", stats.mem),
                    ("memory", stats.memory),
                ];
                for (suffix, value) in suffixes {
                    if let Some(value) = value {
                        out.push(metric(
                            &format!("node_sockstat_{proto}_{suffix}"),
                            format!("Number of {proto} sockets in state {suffix}."),
                            value as f64,
                        ));
                    }
                }
                // mem 按页计数，换算为字节输出
                if let Some(mem) = stats.mem {
                    out.push(metric(
                        &format!("node_sockstat_{proto}_mem_bytes"),
                        format!("Number of {proto} sockets in state mem_bytes."),
                        mem as f64 * bytes_per_page,
                    ));
                }
            }
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
        let collector = SockstatCollector::with_root(fixture_root());
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
        // IPv4
        assert_eq!(value("node_sockstat_sockets_used"), 229.0);
        assert_eq!(value("node_sockstat_TCP_inuse"), 4.0);
        assert_eq!(value("node_sockstat_TCP_tw"), 4.0);
        assert_eq!(value("node_sockstat_TCP_alloc"), 17.0);
        assert_eq!(value("node_sockstat_TCP_mem"), 1.0);
        assert_eq!(value("node_sockstat_TCP_mem_bytes"), page_size() as f64);
        assert_eq!(value("node_sockstat_UDP_inuse"), 0.0);
        assert_eq!(value("node_sockstat_FRAG_memory"), 0.0);
        // IPv6
        assert_eq!(value("node_sockstat_TCP6_inuse"), 17.0);
        assert_eq!(value("node_sockstat_UDP6_inuse"), 9.0);
        assert_eq!(value("node_sockstat_RAW6_inuse"), 1.0);
        assert_eq!(value("node_sockstat_FRAG6_inuse"), 0.0);
    }

    #[test]
    fn test_parse_ignores_unknown_keys() {
        let stat = parse_sockstat("TCP: inuse 1 future_field 2 mem 3\n")
            .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stat.protocols[0].0, "TCP");
        assert_eq!(stat.protocols[0].1.in_use, Some(1));
        assert_eq!(stat.protocols[0].1.mem, Some(3));
    }

    #[test]
    fn test_missing_both_files_no_error() {
        // 两侧文件均缺失 → 无样本输出，不报错（对齐 Go）
        let collector = SockstatCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }
}
