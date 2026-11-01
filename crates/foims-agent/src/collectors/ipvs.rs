//! ipvs 采集器：IPVS（IP Virtual Server）负载均衡统计。
//!
//! 对齐 node_exporter `ipvs_linux.go`（默认启用）与 procfs ipvs.go
//! （v0.23.0），输出：
//! - 5 个 Counter（/proc/net/ip_vs_stats 十六进制解析）：
//!   `node_ipvs_connections_total`、`node_ipvs_incoming_packets_total`、
//!   `node_ipvs_outgoing_packets_total`、`node_ipvs_incoming_bytes_total`、
//!   `node_ipvs_outgoing_bytes_total`；
//! - 3 个 Gauge（/proc/net/ip_vs 逐行解析，按 6 标签组合聚合求和）：
//!   `node_ipvs_backend_connections_active`、
//!   `node_ipvs_backend_connections_inactive`、`node_ipvs_backend_weight`，
//!   标签 local_address/local_port/remote_address/remote_port/proto/
//!   local_mark；FWM 服务的 local_address 记空串、local_port 记 "0"。
//!
//! 偏离点：
//! - 未移植 `--collector.ipvs.backend-labels` 标签裁剪 CLI 参数（固定输出
//!   全部 6 个标签）；
//! - ip_vs_stats 或 ip_vs 缺失时返回空指标族（Go 侧为 ErrNoData 或报错）；
//! - 后端按标签组合的字典序输出（Go map 遍历无序，仅为输出稳定性）。

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// IPVS 后端状态文件（相对 proc_path）
const IPVS_FILE: &str = "net/ip_vs";
/// IPVS 总计文件（相对 proc_path）
const IPVS_STATS_FILE: &str = "net/ip_vs_stats";
/// 后端标签序（对齐 Go fullIpvsBackendLabels）
const BACKEND_LABELS: [&str; 6] = [
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "proto",
    "local_mark",
];

/// 单个 virtual/real 地址对的连接状态（对应 procfs IPVSBackendStatus）
struct BackendStatus {
    local_address: String,
    local_port: u16,
    local_mark: String,
    remote_address: String,
    remote_port: u16,
    proto: String,
    active_conn: u64,
    inact_conn: u64,
    weight: u64,
}

/// 后端聚合结果（按标签组合求和，保留标签值用于输出）
struct BackendSum {
    active: u64,
    inactive: u64,
    weight: u64,
    labels: Vec<String>,
}

pub struct IpvsCollector {
    proc_path: PathBuf,
}

impl IpvsCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for IpvsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 构造 ip_vs_stats 解析错误
fn stats_error(reason: &str) -> CollectorError {
    CollectorError::Parse {
        file: IPVS_STATS_FILE,
        reason: reason.to_string(),
    }
}

/// 构造 ip_vs 解析错误
fn ipvs_error(reason: String) -> CollectorError {
    CollectorError::Parse {
        file: IPVS_FILE,
        reason,
    }
}

/// 解析 /proc/net/ip_vs_stats（对齐 procfs parseIPVSStats：按 \n 分 4 段，
/// 第 3 段须为 5 个十六进制字段）
fn parse_ip_vs_stats(content: &str) -> Result<[u64; 5], CollectorError> {
    let parts: Vec<&str> = content.splitn(4, '\n').collect();
    if parts.len() != 4 {
        return Err(stats_error("ip_vs_stats corrupt: too short"));
    }
    let fields: Vec<&str> = parts[2].split_whitespace().collect();
    if fields.len() != 5 {
        return Err(stats_error(
            "ip_vs_stats corrupt: unexpected number of fields",
        ));
    }
    let mut totals = [0u64; 5];
    for (total, field) in totals.iter_mut().zip(fields) {
        *total = u64::from_str_radix(field, 16).map_err(|_| stats_error("计数字段非法"))?;
    }
    Ok(totals)
}

/// 解析 "IP:PORT" 记号（对齐 procfs parseIPPort：13 字节为 IPv4 十六进制、
/// 46 字节为 IPv6，端口恒为末 4 位十六进制）
fn parse_ip_port(token: &str) -> Result<(String, u16), CollectorError> {
    let address = match token.len() {
        13 => {
            // 8 位十六进制 = 4 字节点分十进制（对齐 Go hex.DecodeString）
            let Some(hex_part) = token.get(..8) else {
                return Err(ipvs_error(format!("Unexpected IP:Port {token}")));
            };
            let mut octets = [0u8; 4];
            for (index, octet) in octets.iter_mut().enumerate() {
                let Some(slice) = hex_part.get(index * 2..index * 2 + 2) else {
                    return Err(ipvs_error(format!("Unexpected IP:Port {token}")));
                };
                *octet = u8::from_str_radix(slice, 16)
                    .map_err(|error| ipvs_error(format!("非法 IPv4 十六进制 {slice}: {error}")))?;
            }
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        46 => {
            // 对齐 Go net.ParseIP(s[1:40])
            let Some(text) = token.get(1..40) else {
                return Err(ipvs_error(format!("Unexpected IP:Port {token}")));
            };
            text.parse::<Ipv6Addr>()
                .map_err(|error| ipvs_error(format!("非法 IPv6 地址 {text}: {error}")))?
                .to_string()
        }
        _ => return Err(ipvs_error(format!("Unexpected IP:Port {token}"))),
    };
    // 端口恒取末 4 位十六进制（对齐 Go s[len(s)-4:]）
    let port_part = token
        .get(token.len().saturating_sub(4)..)
        .ok_or_else(|| ipvs_error(format!("Unexpected port string format {token}")))?;
    if port_part.len() != 4 {
        return Err(ipvs_error(format!(
            "Unexpected port string format {port_part}"
        )));
    }
    let port = u16::from_str_radix(port_part, 16)
        .map_err(|error| ipvs_error(format!("非法端口 {port_part}: {error}")))?;
    Ok((address, port))
}

/// 解析 /proc/net/ip_vs（对齐 procfs parseIPVSBackendStatus 的逐行状态机：
/// 服务行 TCP/UDP/FWM 更新本地上下文，"->" 行携带远端并产出记录）
fn parse_ip_vs_backends(content: &str) -> Result<Vec<BackendStatus>, CollectorError> {
    let mut backends = Vec::new();
    let mut proto = String::new();
    let mut local_mark = String::new();
    let mut local_address = String::new();
    let mut local_port = 0u16;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() < 2 {
            return Err(ipvs_error(format!("Malformed line {line:?}")));
        }
        if fields[0] == "IP" || fields[0] == "Prot" || fields[1] == "RemoteAddress:Port" {
            continue;
        }
        match fields[0] {
            "TCP" | "UDP" => {
                proto = fields[0].to_string();
                local_mark.clear();
                let (address, port) = parse_ip_port(fields[1])?;
                local_address = address;
                local_port = port;
            }
            "FWM" => {
                proto = fields[0].to_string();
                local_mark = fields[1].to_string();
                local_address.clear();
                local_port = 0;
            }
            "->" => {
                if fields.len() < 6 {
                    continue;
                }
                let (remote_address, remote_port) = parse_ip_port(fields[1])?;
                let weight = fields[3]
                    .parse::<u64>()
                    .map_err(|error| ipvs_error(format!("非法 weight {line:?}: {error}")))?;
                let active_conn = fields[4]
                    .parse::<u64>()
                    .map_err(|error| ipvs_error(format!("非法 ActiveConn {line:?}: {error}")))?;
                let inact_conn = fields[5]
                    .parse::<u64>()
                    .map_err(|error| ipvs_error(format!("非法 InActConn {line:?}: {error}")))?;
                backends.push(BackendStatus {
                    local_address: local_address.clone(),
                    local_port,
                    local_mark: local_mark.clone(),
                    remote_address,
                    remote_port,
                    proto: proto.clone(),
                    active_conn,
                    inact_conn,
                    weight,
                });
            }
            _ => {}
        }
    }
    Ok(backends)
}

impl Collector for IpvsCollector {
    fn name(&self) -> &'static str {
        "ipvs"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let stats_path = self.proc_path.join(IPVS_STATS_FILE);
        let totals = match std::fs::read_to_string(&stats_path) {
            Ok(content) => parse_ip_vs_stats(&content)?,
            // ip_vs_stats 缺失（未启用 IPVS）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };

        let mut connections = MetricFamily::new(
            "node_ipvs_connections_total",
            "The total number of connections made.",
            MetricType::Counter,
        );
        let mut incoming_packets = MetricFamily::new(
            "node_ipvs_incoming_packets_total",
            "The total number of incoming packets.",
            MetricType::Counter,
        );
        let mut outgoing_packets = MetricFamily::new(
            "node_ipvs_outgoing_packets_total",
            "The total number of outgoing packets.",
            MetricType::Counter,
        );
        let mut incoming_bytes = MetricFamily::new(
            "node_ipvs_incoming_bytes_total",
            "The total amount of incoming data.",
            MetricType::Counter,
        );
        let mut outgoing_bytes = MetricFamily::new(
            "node_ipvs_outgoing_bytes_total",
            "The total amount of outgoing data.",
            MetricType::Counter,
        );
        connections.push(totals[0] as f64);
        incoming_packets.push(totals[1] as f64);
        outgoing_packets.push(totals[2] as f64);
        incoming_bytes.push(totals[3] as f64);
        outgoing_bytes.push(totals[4] as f64);

        let mut active = MetricFamily::new(
            "node_ipvs_backend_connections_active",
            "The current active connections by local and remote address.",
            MetricType::Gauge,
        );
        let mut inactive = MetricFamily::new(
            "node_ipvs_backend_connections_inactive",
            "The current inactive connections by local and remote address.",
            MetricType::Gauge,
        );
        let mut weight = MetricFamily::new(
            "node_ipvs_backend_weight",
            "The current backend weight by local and remote address.",
            MetricType::Gauge,
        );

        let ipvs_path = self.proc_path.join(IPVS_FILE);
        match std::fs::read_to_string(&ipvs_path) {
            Ok(content) => {
                let backends = parse_ip_vs_backends(&content)?;
                // 按标签组合聚合（对齐 Go：key 为标签值以 '-' 连接）
                let mut sums: HashMap<String, BackendSum> = HashMap::new();
                for backend in &backends {
                    let labels = vec![
                        backend.local_address.clone(),
                        backend.local_port.to_string(),
                        backend.remote_address.clone(),
                        backend.remote_port.to_string(),
                        backend.proto.clone(),
                        backend.local_mark.clone(),
                    ];
                    let key = labels.join("-");
                    let sum = sums.entry(key).or_insert(BackendSum {
                        active: 0,
                        inactive: 0,
                        weight: 0,
                        labels,
                    });
                    sum.active += backend.active_conn;
                    sum.inactive += backend.inact_conn;
                    sum.weight += backend.weight;
                }
                // 后端按标签组合字典序输出（Go map 遍历无序）
                let mut keys: Vec<&String> = sums.keys().collect();
                keys.sort();
                for key in keys {
                    let sum = &sums[key];
                    let labels: Vec<(String, String)> = BACKEND_LABELS
                        .iter()
                        .zip(&sum.labels)
                        .map(|(name, value)| (name.to_string(), value.clone()))
                        .collect();
                    active.push_labeled(labels.clone(), sum.active as f64);
                    inactive.push_labeled(labels.clone(), sum.inactive as f64);
                    weight.push_labeled(labels, sum.weight as f64);
                }
            }
            // ip_vs 缺失 → 后端三族保持为空
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        Ok(vec![
            connections,
            incoming_packets,
            outgoing_packets,
            incoming_bytes,
            outgoing_bytes,
            active,
            inactive,
            weight,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_proc() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    /// 按完整标签集定位样本值
    fn value_of(family: &MetricFamily, labels: &[(&str, &str)]) -> f64 {
        family
            .samples
            .iter()
            .find(|sample| {
                sample.labels.len() == labels.len()
                    && sample
                        .labels
                        .iter()
                        .all(|(key, value)| labels.iter().any(|(k, v)| k == key && v == value))
            })
            .unwrap_or_else(|| panic!("缺少样本 {labels:?}"))
            .value
    }

    /// 按 local_address + remote_address 定位后端样本值
    fn backend_value(family: &MetricFamily, local: &str, remote: &str) -> f64 {
        family
            .samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(key, value)| key == "local_address" && value == local)
                    && sample
                        .labels
                        .iter()
                        .any(|(key, value)| key == "remote_address" && value == remote)
            })
            .unwrap_or_else(|| panic!("缺少后端样本 {local} -> {remote}"))
            .value
    }

    /// 对齐 Go ipvs_linux_test.go 黄金文件 fixtures/ip_vs_result.txt
    #[test]
    fn test_collect_matches_fixture() {
        let collector = IpvsCollector::with_root(fixture_proc());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 8);

        // 总计 5 项（十六进制解析：0x16AA370 等）
        assert_eq!(families[0].name, "node_ipvs_connections_total");
        assert_eq!(families[0].samples.len(), 1);
        assert_eq!(families[0].samples[0].value, 23765872.0);
        assert_eq!(families[1].samples[0].value, 3811989221.0);
        assert_eq!(families[2].samples[0].value, 0.0);
        assert_eq!(families[3].samples[0].value, 89991519156915.0);
        assert_eq!(families[4].samples[0].value, 0.0);

        // 后端 10 个 virtual/real 对（FWM 的 local_address 为空串）
        assert_eq!(families[5].name, "node_ipvs_backend_connections_active");
        assert_eq!(families[5].samples.len(), 10);
        assert_eq!(
            value_of(
                &families[5],
                &[
                    ("local_address", ""),
                    ("local_port", "0"),
                    ("remote_address", "192.168.49.32"),
                    ("remote_port", "3306"),
                    ("proto", "FWM"),
                    ("local_mark", "10001000"),
                ]
            ),
            321.0
        );
        assert_eq!(backend_value(&families[5], "", "192.168.50.26"), 64.0);
        assert_eq!(
            backend_value(&families[5], "192.168.0.22", "192.168.82.22"),
            248.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.22", "192.168.83.21"),
            248.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.22", "192.168.83.24"),
            248.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.55", "192.168.49.32"),
            0.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.55", "192.168.50.26"),
            0.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.57", "192.168.50.21"),
            1498.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.57", "192.168.82.21"),
            1499.0
        );
        assert_eq!(
            backend_value(&families[5], "192.168.0.57", "192.168.84.22"),
            0.0
        );

        // inactive 与 weight
        assert_eq!(families[6].samples.len(), 10);
        assert_eq!(backend_value(&families[6], "", "192.168.49.32"), 5.0);
        assert_eq!(backend_value(&families[6], "", "192.168.50.26"), 1.0);
        assert_eq!(
            backend_value(&families[6], "192.168.0.22", "192.168.83.24"),
            2.0
        );
        assert_eq!(
            backend_value(&families[6], "192.168.0.57", "192.168.50.21"),
            0.0
        );
        assert_eq!(families[7].samples.len(), 10);
        assert_eq!(backend_value(&families[7], "", "192.168.49.32"), 100.0);
        assert_eq!(backend_value(&families[7], "", "192.168.50.26"), 20.0);
        assert_eq!(
            backend_value(&families[7], "192.168.0.55", "192.168.50.26"),
            0.0
        );
        assert_eq!(
            backend_value(&families[7], "192.168.0.57", "192.168.84.22"),
            0.0
        );

        // 排序稳定性：首个样本为 FWM 192.168.49.32（对齐黄金文件行序）
        let first = &families[5].samples[0];
        assert_eq!(
            first.labels[0],
            ("local_address".to_string(), String::new())
        );
        assert_eq!(
            first.labels[3],
            ("remote_port".to_string(), "3306".to_string())
        );
        assert_eq!(first.labels[4], ("proto".to_string(), "FWM".to_string()));
    }

    /// ip_vs_stats 解析错误（段数/字段数不足）按 Parse 错误处理
    #[test]
    fn test_parse_ip_vs_stats_errors() {
        assert!(matches!(
            parse_ip_vs_stats("too\nshort"),
            Err(CollectorError::Parse { .. })
        ));
        let bad_fields = "a\nb\n 1 2 3\n rest\nof it";
        assert!(matches!(
            parse_ip_vs_stats(bad_fields),
            Err(CollectorError::Parse { .. })
        ));
        let bad_hex = "a\nb\n 1 2 3 4 zz\n rest\nof it";
        assert!(matches!(
            parse_ip_vs_stats(bad_hex),
            Err(CollectorError::Parse { .. })
        ));
    }

    /// ip_vs 后端解析：畸形行报错，表头跳过，"->" 字段不足跳过
    #[test]
    fn test_parse_ip_vs_backends_errors() {
        // 字段数 < 2 的行报错（对齐 Go Malformed line）
        let malformed = "Prot LocalAddress:Port\nTCP\n";
        assert!(matches!(
            parse_ip_vs_backends(malformed),
            Err(CollectorError::Parse { .. })
        ));
        // 非法 weight 报错
        let bad_weight = "TCP  C0A80016:0CEA wlc\n  -> C0A85216:0CEA Tunnel xx 1 2\n";
        assert!(matches!(
            parse_ip_vs_backends(bad_weight),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_parse_ip_port() {
        let (address, port) =
            parse_ip_port("C0A80016:0CEA").unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(address, "192.168.0.22");
        assert_eq!(port, 3306);
        assert!(parse_ip_port("C0A8:0CEA").is_err());
    }

    #[test]
    fn test_missing_files_yield_empty() {
        let collector = IpvsCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }
}
