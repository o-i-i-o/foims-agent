//! nfs 采集器：NFS 客户端 RPC 统计（/proc/net/rpc/nfs）。
//!
//! 对齐 node_exporter `nfs_linux.go`（默认启用）与 procfs nfs 包
//! （v0.23.0：nfs.go / parse.go / parse_nfs.go）。本模块同时承担 procfs nfs
//! 包的 Rust 实现，nfsd 采集器复用此处的共享解析（proc2/proc3 行两侧格式
//! 相同）。输出：
//! - 5 个 Counter：`node_nfs_packets_total`（标签 protocol=udp/tcp）、
//!   `node_nfs_connections_total`、`node_nfs_rpcs_total`、
//!   `node_nfs_rpc_retransmissions_total`、
//!   `node_nfs_rpc_authentication_refreshes_total`；
//! - `node_nfs_requests_total`（Counter，标签 proto/method）：proc2（18）、
//!   proc3（22）、proc4（59）各行的全部字段，method 名逐字对齐 Go 结构体
//!   字段声明（Go 侧经 reflect 按声明序遍历）。
//!
//! 偏离点：
//! - /proc/net/rpc/nfs 缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - 同一 key 的行出现多次时后者覆盖前者（对齐 Go 结构体赋值语义）；
//! - 解析错误 reason 保留 Go 原文（invalid/unknown NFS metric line 等）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// NFS 客户端统计文件（相对 proc_path）
const NFS_FILE: &str = "net/rpc/nfs";

/// proc2 行字段名（对齐 procfs V2Stats 字段声明序）
pub(crate) const V2_METHODS: [&str; 18] = [
    "Null", "GetAttr", "SetAttr", "Root", "Lookup", "ReadLink", "Read", "WrCache", "Write",
    "Create", "Remove", "Rename", "Link", "SymLink", "MkDir", "RmDir", "ReadDir", "FsStat",
];

/// proc3 行字段名（对齐 procfs V3Stats 字段声明序）
pub(crate) const V3_METHODS: [&str; 22] = [
    "Null",
    "GetAttr",
    "SetAttr",
    "Lookup",
    "Access",
    "ReadLink",
    "Read",
    "Write",
    "Create",
    "MkDir",
    "SymLink",
    "MkNod",
    "Remove",
    "RmDir",
    "Rename",
    "Link",
    "ReadDir",
    "ReadDirPlus",
    "FsStat",
    "FsInfo",
    "PathConf",
    "Commit",
];

/// proc4 行字段名（对齐 procfs ClientV4Stats 字段声明序，共 59 个）
pub(crate) const V4_METHODS: [&str; 59] = [
    "Null",
    "Read",
    "Write",
    "Commit",
    "Open",
    "OpenConfirm",
    "OpenNoattr",
    "OpenDowngrade",
    "Close",
    "Setattr",
    "FsInfo",
    "Renew",
    "SetClientID",
    "SetClientIDConfirm",
    "Lock",
    "Lockt",
    "Locku",
    "Access",
    "Getattr",
    "Lookup",
    "LookupRoot",
    "Remove",
    "Rename",
    "Link",
    "Symlink",
    "Create",
    "Pathconf",
    "StatFs",
    "ReadLink",
    "ReadDir",
    "ServerCaps",
    "DelegReturn",
    "GetACL",
    "SetACL",
    "FsLocations",
    "ReleaseLockowner",
    "Secinfo",
    "FsidPresent",
    "ExchangeID",
    "CreateSession",
    "DestroySession",
    "Sequence",
    "GetLeaseTime",
    "ReclaimComplete",
    "LayoutGet",
    "GetDeviceInfo",
    "LayoutCommit",
    "LayoutReturn",
    "SecinfoNoName",
    "TestStateID",
    "FreeStateID",
    "GetDeviceList",
    "BindConnToSession",
    "DestroyClientID",
    "Seek",
    "Allocate",
    "DeAllocate",
    "LayoutStats",
    "Clone",
];

/// /proc/net/rpc/nfs 解析结果（对齐 procfs ClientRPCStats；net/rpc/proc2/
/// proc3/proc4 首列为计数字段，解析后移除）
#[derive(Debug)]
pub(crate) struct ClientRpcStats {
    /// net 行：net_count/udp_count/tcp_count/tcp_connect
    pub network: [u64; 4],
    /// rpc 行：rpc_count/retransmissions/auth_refreshes
    pub rpc: [u64; 3],
    /// proc2 行（18 个方法）
    pub v2: [u64; 18],
    /// proc3 行（22 个方法）
    pub v3: [u64; 22],
    /// proc4 行（59 个方法；旧内核字段不足时尾部补 0）
    pub v4: [u64; 59],
}

impl Default for ClientRpcStats {
    fn default() -> Self {
        Self {
            network: [0; 4],
            rpc: [0; 3],
            v2: [0; 18],
            v3: [0; 22],
            v4: [0; 59],
        }
    }
}

/// 构造 NFS 统计解析错误
fn parse_error(reason: String) -> CollectorError {
    CollectorError::Parse {
        file: NFS_FILE,
        reason,
    }
}

/// 对齐 procfs parsers.ParseUint64s：十进制 u64 逐个解析
pub(crate) fn parse_uint64s(fields: &[&str], prefix: &str) -> Result<Vec<u64>, CollectorError> {
    let mut values = Vec::with_capacity(fields.len());
    for field in fields {
        let value = field
            .parse::<u64>()
            .map_err(|error| parse_error(format!("{prefix}: 非法数值 {field:?}: {error}")))?;
        values.push(value);
    }
    Ok(values)
}

/// 对齐 procfs parseNetwork：net 行固定 4 个字段（nfs/nfsd 的 net 行格式相同）
pub(crate) fn parse_network(
    values: &[u64],
    file: &'static str,
) -> Result<[u64; 4], CollectorError> {
    if values.len() != 4 {
        return Err(CollectorError::Parse {
            file,
            reason: format!("invalid Network line {values:?}"),
        });
    }
    let mut network = [0u64; 4];
    network.copy_from_slice(values);
    Ok(network)
}

/// 对齐 procfs parseClientRPC：rpc 行固定 3 个字段
fn parse_client_rpc(values: &[u64]) -> Result<[u64; 3], CollectorError> {
    if values.len() != 3 {
        return Err(parse_error(format!("invalid RPC line {values:?}")));
    }
    let mut rpc = [0u64; 3];
    rpc.copy_from_slice(values);
    Ok(rpc)
}

/// proc2/proc3 行的公共解析：首列为方法数 count，须满足
/// len(v[1:]) == count 且 count >= expected（对齐 Go parseV2Stats/parseV3Stats；
/// nfs/nfsd 的 proc2/proc3 行格式相同，错误归属调用方文件）
pub(crate) fn parse_proc_stats(
    values: &[u64],
    expected: usize,
    line: &str,
    file: &'static str,
) -> Result<Vec<u64>, CollectorError> {
    let count = values[0] as usize;
    if values.len() - 1 != count || count < expected {
        return Err(CollectorError::Parse {
            file,
            reason: format!("invalid {line} line {values:?}"),
        });
    }
    Ok(values[1..].to_vec())
}

/// 对齐 procfs parseClientV4Stats：旧内核字段不足 59 时补 0 到 60（含首列
/// 计数），多于 59 时忽略尾部
fn parse_client_v4(values: &[u64]) -> Result<[u64; 59], CollectorError> {
    let count = values[0] as usize;
    if values.len() - 1 != count {
        return Err(parse_error(format!(
            "invalid ClientV4Stats line {values:?}"
        )));
    }
    let mut padded = [0u64; 60];
    for (slot, value) in padded.iter_mut().zip(values) {
        *slot = *value;
    }
    let mut v4 = [0u64; 59];
    v4.copy_from_slice(&padded[1..]);
    // 对齐 Go parseClientV4Stats 的赋值序与 ClientV4Stats 声明序错位：
    // LayoutGet（声明序 44）取 v[46]、GetDeviceInfo（声明序 45）取 v[45]，
    // 恰为自然序上这两格互换
    v4.swap(44, 45);
    Ok(v4)
}

/// 解析 /proc/net/rpc/nfs 全文（对齐 procfs ParseClientRPCStats 的逐行分发）
fn parse_client_rpc_stats(content: &str) -> Result<ClientRpcStats, CollectorError> {
    let mut stats = ClientRpcStats::default();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 至少要求 <key> <value>（对齐 Go：len(parts) < 2 报错）
        if fields.len() < 2 {
            return Err(parse_error(format!("invalid NFS metric line {line:?}")));
        }
        let values = parse_uint64s(&fields[1..], "error parsing NFS metric line")?;
        match fields[0] {
            "net" => stats.network = parse_network(&values, NFS_FILE)?,
            "rpc" => stats.rpc = parse_client_rpc(&values)?,
            "proc2" => {
                let methods = parse_proc_stats(&values, 18, "V2Stats", NFS_FILE)?;
                for (slot, value) in stats.v2.iter_mut().zip(methods) {
                    *slot = value;
                }
            }
            "proc3" => {
                let methods = parse_proc_stats(&values, 22, "V3Stats", NFS_FILE)?;
                for (slot, value) in stats.v3.iter_mut().zip(methods) {
                    *slot = value;
                }
            }
            "proc4" => stats.v4 = parse_client_v4(&values)?,
            unknown => return Err(parse_error(format!("unknown NFS metric line {unknown:?}"))),
        }
    }
    Ok(stats)
}

/// 按 proto/method 推送 requests 样本（对齐 Go updateNFSRequestsv*Stats 的
/// reflect 遍历：字段声明序即 method 名序）
fn push_requests(family: &mut MetricFamily, proto: &str, methods: &[&str], values: &[u64]) {
    for (method, value) in methods.iter().zip(values) {
        family.push_labeled(
            vec![
                ("proto".to_string(), proto.to_string()),
                ("method".to_string(), (*method).to_string()),
            ],
            *value as f64,
        );
    }
}

pub struct NfsCollector {
    proc_path: PathBuf,
}

impl NfsCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for NfsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for NfsCollector {
    fn name(&self) -> &'static str {
        "nfs"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let nfs_path = self.proc_path.join(NFS_FILE);
        let content = match std::fs::read_to_string(&nfs_path) {
            Ok(content) => content,
            // 统计文件缺失（NFS 未使用）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let stats = parse_client_rpc_stats(&content)?;

        let mut packets = MetricFamily::new(
            "node_nfs_packets_total",
            "Total NFSd network packets (sent+received) by protocol type.",
            MetricType::Counter,
        );
        packets.push_labeled(
            vec![("protocol".to_string(), "udp".to_string())],
            stats.network[1] as f64,
        );
        packets.push_labeled(
            vec![("protocol".to_string(), "tcp".to_string())],
            stats.network[2] as f64,
        );

        let mut connections = MetricFamily::new(
            "node_nfs_connections_total",
            "Total number of NFSd TCP connections.",
            MetricType::Counter,
        );
        connections.push(stats.network[3] as f64);

        let mut rpcs = MetricFamily::new(
            "node_nfs_rpcs_total",
            "Total number of RPCs performed.",
            MetricType::Counter,
        );
        rpcs.push(stats.rpc[0] as f64);

        let mut retransmissions = MetricFamily::new(
            "node_nfs_rpc_retransmissions_total",
            "Number of RPC transmissions performed.",
            MetricType::Counter,
        );
        retransmissions.push(stats.rpc[1] as f64);

        let mut auth_refreshes = MetricFamily::new(
            "node_nfs_rpc_authentication_refreshes_total",
            "Number of RPC authentication refreshes performed.",
            MetricType::Counter,
        );
        auth_refreshes.push(stats.rpc[2] as f64);

        let mut requests = MetricFamily::new(
            "node_nfs_requests_total",
            "Number of NFS procedures invoked.",
            MetricType::Counter,
        );
        push_requests(&mut requests, "2", &V2_METHODS, &stats.v2);
        push_requests(&mut requests, "3", &V3_METHODS, &stats.v3);
        push_requests(&mut requests, "4", &V4_METHODS, &stats.v4);

        Ok(vec![
            packets,
            connections,
            rpcs,
            retransmissions,
            auth_refreshes,
            requests,
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

    /// 按 method 定位 requests 样本值
    fn request_of(family: &MetricFamily, proto: &str, method: &str) -> f64 {
        value_of(family, &[("proto", proto), ("method", method)])
    }

    /// 对齐 e2e-output.txt 的 node_nfs 段黄金期望（fixture 与上游一致）
    #[test]
    fn test_collect_matches_fixture() {
        let collector = NfsCollector::with_root(fixture_proc());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 6);

        // network：udp=70 tcp=69 connections=45
        assert_eq!(families[0].name, "node_nfs_packets_total");
        assert_eq!(families[0].samples.len(), 2);
        assert_eq!(value_of(&families[0], &[("protocol", "udp")]), 70.0);
        assert_eq!(value_of(&families[0], &[("protocol", "tcp")]), 69.0);
        assert_eq!(families[1].samples[0].value, 45.0);

        // rpc：rpcs=1218785755 retransmissions=374636 auth_refreshes=1218815394
        assert_eq!(families[2].samples[0].value, 1_218_785_755.0);
        assert_eq!(families[3].samples[0].value, 374_636.0);
        assert_eq!(families[4].samples[0].value, 1_218_815_394.0);

        // requests：18 + 22 + 59 = 99 个样本
        assert_eq!(families[5].name, "node_nfs_requests_total");
        assert_eq!(families[5].samples.len(), 99);

        // proto2 抽查（proc2 行逐字段）
        assert_eq!(request_of(&families[5], "2", "Null"), 16.0);
        assert_eq!(request_of(&families[5], "2", "GetAttr"), 57.0);
        assert_eq!(request_of(&families[5], "2", "Root"), 52.0);
        assert_eq!(request_of(&families[5], "2", "WrCache"), 86.0);
        assert_eq!(request_of(&families[5], "2", "SymLink"), 53.0);
        assert_eq!(request_of(&families[5], "2", "FsStat"), 82.0);

        // proto3 抽查
        assert_eq!(request_of(&families[5], "3", "Null"), 0.0);
        assert_eq!(request_of(&families[5], "3", "GetAttr"), 1_061_909_262.0);
        assert_eq!(request_of(&families[5], "3", "Access"), 117_661_341.0);
        assert_eq!(request_of(&families[5], "3", "Read"), 29_391_916.0);
        assert_eq!(request_of(&families[5], "3", "MkNod"), 0.0);
        assert_eq!(request_of(&families[5], "3", "ReadDirPlus"), 92_385.0);
        assert_eq!(request_of(&families[5], "3", "Commit"), 23_729.0);

        // proto4 抽查（fixture 48 个字段 < 59，尾部按 0 补齐）
        assert_eq!(request_of(&families[5], "4", "Null"), 98.0);
        assert_eq!(request_of(&families[5], "4", "Close"), 28.0);
        assert_eq!(request_of(&families[5], "4", "Access"), 58.0);
        assert_eq!(request_of(&families[5], "4", "Getattr"), 88.0);
        assert_eq!(request_of(&families[5], "4", "FsidPresent"), 11.0);
        assert_eq!(request_of(&families[5], "4", "ReclaimComplete"), 35.0);
        assert_eq!(request_of(&families[5], "4", "GetDeviceInfo"), 1.0);
        assert_eq!(request_of(&families[5], "4", "LayoutGet"), 90.0);
        assert_eq!(request_of(&families[5], "4", "LayoutReturn"), 0.0);
        assert_eq!(request_of(&families[5], "4", "LayoutStats"), 0.0);
        assert_eq!(request_of(&families[5], "4", "Clone"), 0.0);
    }

    /// 文件缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_file_yields_empty() {
        let collector = NfsCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    /// 对齐 ParseClientRPCStats 的错误语义：行字段不足、非法数值、未知 key
    #[test]
    fn test_parse_errors() {
        // len(parts) < 2
        assert!(matches!(
            parse_client_rpc_stats("net"),
            Err(CollectorError::Parse { .. })
        ));
        // 非法数值（负数不满足 ParseUint）
        assert!(matches!(
            parse_client_rpc_stats("net -1 2 3 4"),
            Err(CollectorError::Parse { .. })
        ));
        // 未知 key
        assert!(matches!(
            parse_client_rpc_stats("bogus 1 2"),
            Err(CollectorError::Parse { .. })
        ));
        // net 行字段数不为 4
        assert!(matches!(
            parse_client_rpc_stats("net 1 2 3"),
            Err(CollectorError::Parse { .. })
        ));
        // rpc 行字段数不为 3
        assert!(matches!(
            parse_client_rpc_stats("rpc 1 2 3 4"),
            Err(CollectorError::Parse { .. })
        ));
    }

    /// proc2/proc3 首列计数与字段数不一致时报错
    #[test]
    fn test_parse_proc_stats_errors() {
        // 计数 18 与实际 17 个字段不一致
        assert!(matches!(
            parse_client_rpc_stats("proc2 18 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8"),
            Err(CollectorError::Parse { .. })
        ));
        // 计数 17 < 最小值 18
        assert!(matches!(
            parse_client_rpc_stats("proc2 17 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8"),
            Err(CollectorError::Parse { .. })
        ));
        // proc3 最小值 22
        assert!(matches!(
            parse_client_rpc_stats("proc3 21 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3"),
            Err(CollectorError::Parse { .. })
        ));
    }

    /// 旧内核 proc4 字段不足 59 时按 0 补齐（对齐 parseClientV4Stats 的 padding）
    #[test]
    fn test_parse_client_v4_padding() {
        // 计数 2 + 2 个字段：v[1]=10 v[2]=20，其余补 0
        let stats =
            parse_client_rpc_stats("proc4 2 10 20").unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.v4[0], 10);
        assert_eq!(stats.v4[1], 20);
        assert_eq!(stats.v4[58], 0);
        // proc4 计数与字段数不一致报错
        assert!(matches!(
            parse_client_rpc_stats("proc4 3 10 20"),
            Err(CollectorError::Parse { .. })
        ));
    }
}
