//! netstat 采集器：网络协议栈统计。
//!
//! 对齐 node_exporter `netstat_linux.go` + `netstat_descs_linux.go`
//! （默认启用）：读取 /proc/net/netstat、/proc/net/snmp（表头/值两行
//! 一组）与 /proc/net/snmp6（键值行，键按已知协议前缀拆分），输出
//! `node_netstat_<协议>_<字段>`（Untyped，help 为 "Statistic <协议><字段>."，
//! 与 Go 生成的 311 条 descs 逐条一致——help 文案即「Statistic + 去
//! 下划线 key」的统一模式，故无需移植描述符大表）。
//! 默认过滤正则以字符串匹配逻辑等价实现（对齐 --collector.netstat.fields
//! 默认值）；值解析失败的字段跳过（对齐 Go 的 *float64 nil 语义）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 统计文件（相对 proc_path）
const NETSTAT_FILE: &str = "net/netstat";
const SNMP_FILE: &str = "net/snmp";
const SNMP6_FILE: &str = "net/snmp6";

/// snmp6 键的协议前缀（长前缀优先）
const SNMP6_PREFIXES: [&str; 11] = [
    "UdpLite6", "Icmp6", "Udp6", "Ip6", "TcpExt", "IpExt", "UdpLite", "Icmp", "Tcp", "Udp", "Ip",
];

pub struct NetstatCollector {
    proc_path: PathBuf,
}

impl NetstatCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for NetstatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 默认字段过滤（等价于 Go 默认正则
/// ^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|
///   Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|
///   TCPTimeouts|TCPOFOQueue|TCPRcvQDrop)|Tcp_(ActiveOpens|InSegs|OutSegs|
///   OutRsts|PassiveOpens|RetransSegs|CurrEstab)|
///   Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors))$）
fn field_selected(key: &str) -> bool {
    let Some((protocol, field)) = key.split_once('_') else {
        return false;
    };
    // .*_(InErrors|InErrs)
    if key.ends_with("_InErrors") || key.ends_with("_InErrs") {
        return true;
    }
    match protocol {
        "Ip" if field == "Forwarding" => return true,
        "Ip6" | "IpExt" => {
            if field == "InOctets" || field == "OutOctets" {
                return true;
            }
        }
        "Icmp" | "Icmp6" => {
            if field == "InMsgs" || field == "OutMsgs" {
                return true;
            }
        }
        "TcpExt" => {
            if field.starts_with("Listen")
                || field.starts_with("Syncookies")
                || matches!(
                    field,
                    "TCPSynRetrans" | "TCPTimeouts" | "TCPOFOQueue" | "TCPRcvQDrop"
                )
            {
                return true;
            }
        }
        "Tcp" => {
            if matches!(
                field,
                "ActiveOpens"
                    | "InSegs"
                    | "OutSegs"
                    | "OutRsts"
                    | "PassiveOpens"
                    | "RetransSegs"
                    | "CurrEstab"
            ) {
                return true;
            }
        }
        "Udp" | "Udp6" => {
            if matches!(
                field,
                "InDatagrams" | "OutDatagrams" | "NoPorts" | "RcvbufErrors" | "SndbufErrors"
            ) {
                return true;
            }
        }
        _ => {}
    }
    false
}

/// snmp6 键拆分为 (协议, 字段)：按已知协议前缀（长前缀优先）；
/// 无匹配前缀时返回 None
fn split_snmp6_key(key: &str) -> Option<(&str, &str)> {
    for prefix in SNMP6_PREFIXES {
        if let Some(field) = key.strip_prefix(prefix)
            && !field.is_empty()
        {
            return Some((prefix, field));
        }
    }
    None
}

/// 解析表头/值两行一组的统计文本（netstat 与 snmp），
/// 返回 (key, 值) 序列；值解析失败的字段跳过
fn parse_kv_table(lines: &[&str]) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let header = lines[index];
        index += 1;
        // 值行可能缺失（文件尾部截断），跳过该协议
        let Some(values) = lines.get(index) else {
            break;
        };
        index += 1;
        let Some((protocol, header_fields)) = header.split_once(':') else {
            continue;
        };
        let protocol = protocol.trim();
        let value_fields: Vec<&str> = values
            .split_once(':')
            .map(|(_, rest)| rest)
            .unwrap_or(values)
            .split_whitespace()
            .collect();
        for (field, value_text) in header_fields.split_whitespace().zip(value_fields) {
            let Ok(value) = value_text.parse::<f64>() else {
                // 对齐 Go：解析失败的字段为 nil，静默跳过
                continue;
            };
            out.push((format!("{protocol}_{field}"), value));
        }
    }
    out
}

/// 解析 snmp6 文本：`键 值` 行，键按协议前缀拆分
fn parse_snmp6(text: &str) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value_text)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(value) = value_text.parse::<f64>() else {
            continue;
        };
        if let Some((protocol, field)) = split_snmp6_key(key) {
            out.push((format!("{protocol}_{field}"), value));
        }
    }
    out
}

impl Collector for NetstatCollector {
    fn name(&self) -> &'static str {
        "netstat"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let read_text = |file: &str| -> Result<String, CollectorError> {
            Ok(std::fs::read_to_string(self.proc_path.join(file))?)
        };
        let netstat = read_text(NETSTAT_FILE)?;
        let snmp = read_text(SNMP_FILE)?;
        let snmp6 = read_text(SNMP6_FILE)?;

        let mut pairs = Vec::new();
        pairs.extend(parse_kv_table(&netstat.lines().collect::<Vec<_>>()));
        pairs.extend(parse_kv_table(&snmp.lines().collect::<Vec<_>>()));
        pairs.extend(parse_snmp6(&snmp6));

        let mut out = Vec::new();
        for (key, value) in pairs {
            if !field_selected(&key) {
                continue;
            }
            let mut family = MetricFamily::new(
                &format!("node_netstat_{key}"),
                &format!("Statistic {}.", key.replace('_', "")),
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
        let collector = NetstatCollector::with_root(fixture_root());
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
        // 对齐 e2e 期望输出的代表值
        assert_eq!(value("node_netstat_Ip_Forwarding"), 1.0);
        assert_eq!(value("node_netstat_Tcp_ActiveOpens"), 3556.0);
        assert_eq!(value("node_netstat_Tcp_PassiveOpens"), 230.0);
        assert_eq!(value("node_netstat_Tcp_InSegs"), 57_252_008.0);
        assert_eq!(value("node_netstat_Tcp_OutSegs"), 54_915_039.0);
        assert_eq!(value("node_netstat_Tcp_RetransSegs"), 227.0);
        assert_eq!(value("node_netstat_Tcp_InErrs"), 5.0);
        assert_eq!(value("node_netstat_TcpExt_TCPTimeouts"), 115.0);
        assert_eq!(value("node_netstat_TcpExt_ListenDrops"), 0.0);
        assert_eq!(value("node_netstat_IpExt_InOctets"), 6_286_396_970.0);
        assert_eq!(value("node_netstat_Icmp_InMsgs"), 104.0);
        assert_eq!(value("node_netstat_Udp_InDatagrams"), 88_542.0);
        assert_eq!(value("node_netstat_Udp_RcvbufErrors"), 9.0);
        assert_eq!(value("node_netstat_Udp6_RcvbufErrors"), 9.0);
        assert_eq!(value("node_netstat_Ip6_InOctets"), 460.0);
        assert_eq!(value("node_netstat_Icmp6_OutMsgs"), 8.0);
        assert_eq!(value("node_netstat_UdpLite_InErrors"), 0.0);
        assert_eq!(value("node_netstat_UdpLite6_InErrors"), 0.0);
        // help 对齐生成表模式："Statistic <协议><字段>."
        let family = families
            .iter()
            .find(|f| f.name == "node_netstat_Tcp_ActiveOpens")
            .unwrap_or_else(|| panic!("缺少指标"));
        assert_eq!(family.help, "Statistic TcpActiveOpens.");
        assert_eq!(family.mtype, MetricType::Untyped);
    }

    #[test]
    fn test_field_selected() {
        assert!(field_selected("Tcp_InErrs"));
        assert!(field_selected("TcpExt_InErrors"));
        assert!(field_selected("Ip_Forwarding"));
        assert!(field_selected("Ip6_InOctets"));
        assert!(field_selected("IpExt_OutOctets"));
        assert!(field_selected("Icmp_InMsgs"));
        assert!(field_selected("Icmp6_OutMsgs"));
        assert!(field_selected("TcpExt_ListenDrops"));
        assert!(field_selected("TcpExt_SyncookiesSent"));
        assert!(field_selected("TcpExt_TCPOFOQueue"));
        assert!(field_selected("Tcp_CurrEstab"));
        assert!(field_selected("Udp_NoPorts"));
        assert!(field_selected("Udp6_SndbufErrors"));
        // 未命中默认过滤
        assert!(!field_selected("Tcp_RtoAlgorithm"));
        assert!(!field_selected("Ip_InReceives"));
        assert!(!field_selected("TcpExt_TCPRenoRecovery"));
        assert!(!field_selected("IcmpMsg_InType3"));
    }

    #[test]
    fn test_parse_snmp6_prefix_split() {
        let pairs =
            parse_snmp6("Ip6InReceives 100\nIcmp6OutMsgs 8\nUdpLite6InErrors 0\n\n乱键 1\n");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("Ip6_InReceives".to_string(), 100.0));
        assert_eq!(pairs[1], ("Icmp6_OutMsgs".to_string(), 8.0));
        assert_eq!(pairs[2], ("UdpLite6_InErrors".to_string(), 0.0));
    }

    #[test]
    fn test_missing_file_is_error() {
        let collector = NetstatCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
