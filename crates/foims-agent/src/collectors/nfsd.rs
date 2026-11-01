//! nfsd 采集器：NFS 服务端 RPC 统计（/proc/net/rpc/nfsd）。
//!
//! 对齐 node_exporter `nfsd_linux.go`（默认启用）与 procfs nfs 包
//! （v0.23.0：parse.go / parse_nfsd.go）；proc2/proc3/net 行解析复用
//! [`super::nfs`] 的共享实现。输出：
//! - 13 个无名 Counter/Gauge：`node_nfsd_reply_cache_hits_total`、
//!   `node_nfsd_reply_cache_misses_total`、`node_nfsd_reply_cache_nocache_total`、
//!   `node_nfsd_file_handles_stale_total`、`node_nfsd_disk_bytes_read_total`、
//!   `node_nfsd_disk_bytes_written_total`、`node_nfsd_server_threads`（Gauge）、
//!   `node_nfsd_read_ahead_cache_size_blocks`（Gauge）、
//!   `node_nfsd_read_ahead_cache_not_found_total`、
//!   `node_nfsd_packets_total`（标签 proto=udp/tcp）、
//!   `node_nfsd_connections_total`、`node_nfsd_rpc_errors_total`
//!   （标签 error=fmt/auth/cInt）、`node_nfsd_server_rpcs_total`；
//! - `node_nfsd_requests_total`（Counter，标签 proto/method）：proc2（17，
//!   手写推送无 Null）、proc3（21，无 Null）、proc4ops（35 个 NFSv4 操作）、
//!   wdeleg_getattr（proto="4"/method="WdelegGetattr"）。
//!
//! 偏离点：
//! - /proc/net/rpc/nfsd 缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - proc4 行（ServerV4Stats 的 Null/Compound）按 Go 语义解析校验但不输出
//!   任何指标；
//! - 同一 key 的行出现多次时后者覆盖前者（对齐 Go 结构体赋值语义）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::nfs::{parse_network, parse_proc_stats, parse_uint64s};

/// NFS 服务端统计文件（相对 proc_path）
const NFSD_FILE: &str = "net/rpc/nfsd";

/// proc4ops 行中 nfsd 推送的方法名与 V4Ops 值数组索引（对齐 Go
/// updateNFSdRequestsv4Stats 的手写推送序；Op0Unused/Op1Unused/Op2Future/
/// PutPubFH/PutRootFH 不推送，RelLockOwner 来自 v[40] 单独推送）
const V4OPS_METHODS: [(&str, usize); 34] = [
    ("Access", 3),
    ("Close", 4),
    ("Commit", 5),
    ("Create", 6),
    ("DelegPurge", 7),
    ("DelegReturn", 8),
    ("GetAttr", 9),
    ("GetFH", 10),
    ("Link", 11),
    ("Lock", 12),
    ("Lockt", 13),
    ("Locku", 14),
    ("Lookup", 15),
    ("LookupRoot", 16),
    ("Nverify", 17),
    ("Open", 18),
    ("OpenAttr", 19),
    ("OpenConfirm", 20),
    ("OpenDgrd", 21),
    ("PutFH", 22),
    ("Read", 25),
    ("ReadDir", 26),
    ("ReadLink", 27),
    ("Remove", 28),
    ("Rename", 29),
    ("Renew", 30),
    ("RestoreFH", 31),
    ("SaveFH", 32),
    ("SecInfo", 33),
    ("SetAttr", 34),
    ("SetClientID", 35),
    ("SetClientIDConfirm", 36),
    ("Verify", 37),
    ("Write", 38),
];

/// proc2 行中 nfsd 推送的方法名与 V2Stats 值数组索引（对齐 Go
/// updateNFSdRequestsv2Stats 的手写推送序，无 Null）
const NFSD_V2_METHODS: [(&str, usize); 17] = [
    ("GetAttr", 1),
    ("SetAttr", 2),
    ("Root", 3),
    ("Lookup", 4),
    ("ReadLink", 5),
    ("Read", 6),
    ("WrCache", 7),
    ("Write", 8),
    ("Create", 9),
    ("Remove", 10),
    ("Rename", 11),
    ("Link", 12),
    ("SymLink", 13),
    ("MkDir", 14),
    ("RmDir", 15),
    ("ReadDir", 16),
    ("FsStat", 17),
];

/// proc3 行中 nfsd 推送的方法名与 V3Stats 值数组索引（对齐 Go
/// updateNFSdRequestsv3Stats 的手写推送序，无 Null）
const NFSD_V3_METHODS: [(&str, usize); 21] = [
    ("GetAttr", 1),
    ("SetAttr", 2),
    ("Lookup", 3),
    ("Access", 4),
    ("ReadLink", 5),
    ("Read", 6),
    ("Write", 7),
    ("Create", 8),
    ("MkDir", 9),
    ("SymLink", 10),
    ("MkNod", 11),
    ("Remove", 12),
    ("RmDir", 13),
    ("Rename", 14),
    ("Link", 15),
    ("ReadDir", 16),
    ("ReadDirPlus", 17),
    ("FsStat", 18),
    ("FsInfo", 19),
    ("PathConf", 20),
    ("Commit", 21),
];

/// /proc/net/rpc/nfsd 解析结果（对齐 procfs ServerRPCStats）
#[derive(Debug, Default)]
struct ServerRpcStats {
    /// rc 行：hits/misses/no_cache
    reply_cache: [u64; 3],
    /// fh 行：stale/total_lookups/anon_lookups/dir_no_cache/no_dir_no_cache
    file_handles: [u64; 5],
    /// io 行：read/write
    input_output: [u64; 2],
    /// th 行：threads/full_cnt（仅取前 2 个数值，忽略后面的耗时直方图）
    threads: [u64; 2],
    /// ra 行：cache_size/直方图 10 个/not_found（共 12 个）
    read_ahead_cache: [u64; 12],
    /// net 行：net_count/udp_count/tcp_count/tcp_connect
    network: [u64; 4],
    /// rpc 行：rpc_count/bad_cnt/bad_fmt/bad_auth/badc_int
    server_rpc: [u64; 5],
    /// proc2 行（18 个方法）
    v2: [u64; 18],
    /// proc3 行（22 个方法）
    v3: [u64; 22],
    /// proc4 行（ServerV4Stats：null/compound，仅校验不输出）
    v4: [u64; 2],
    /// proc4ops 行：v40ops[0..39] = Op0Unused..Write，rel_lock_owner 单独取
    v4_ops: V4Ops,
    /// wdeleg_getattr 行
    wdeleg_getattr: u64,
}

/// proc4ops 行解析结果（对齐 procfs V4Ops）
#[derive(Debug)]
struct V4Ops {
    /// v[1..40]：Op0Unused..Write 共 39 个值
    values: [u64; 39],
    /// values > 39 时取 v[40]，否则 0（对齐 Go parseV4Ops 的 RelLockOwner）
    rel_lock_owner: u64,
}

impl Default for V4Ops {
    fn default() -> Self {
        Self {
            values: [0; 39],
            rel_lock_owner: 0,
        }
    }
}

/// 构造 NFSd 统计解析错误
fn parse_error(reason: String) -> CollectorError {
    CollectorError::Parse {
        file: NFSD_FILE,
        reason,
    }
}

/// 对齐 procfs parseReplyCache：rc 行固定 3 个字段
fn parse_reply_cache(values: &[u64]) -> Result<[u64; 3], CollectorError> {
    if values.len() != 3 {
        return Err(parse_error(format!("invalid ReplyCache line {values:?}")));
    }
    let mut reply_cache = [0u64; 3];
    reply_cache.copy_from_slice(values);
    Ok(reply_cache)
}

/// 对齐 procfs parseFileHandles：fh 行固定 5 个字段
fn parse_file_handles(values: &[u64]) -> Result<[u64; 5], CollectorError> {
    if values.len() != 5 {
        return Err(parse_error(format!("invalid FileHandles, line {values:?}")));
    }
    let mut file_handles = [0u64; 5];
    file_handles.copy_from_slice(values);
    Ok(file_handles)
}

/// 对齐 procfs parseInputOutput：io 行固定 2 个字段
fn parse_input_output(values: &[u64]) -> Result<[u64; 2], CollectorError> {
    if values.len() != 2 {
        return Err(parse_error(format!("invalid InputOutput line {values:?}")));
    }
    let mut input_output = [0u64; 2];
    input_output.copy_from_slice(values);
    Ok(input_output)
}

/// 对齐 procfs parseThreads：th 行固定 2 个字段
fn parse_threads(values: &[u64]) -> Result<[u64; 2], CollectorError> {
    if values.len() != 2 {
        return Err(parse_error(format!("invalid Threads line {values:?}")));
    }
    let mut threads = [0u64; 2];
    threads.copy_from_slice(values);
    Ok(threads)
}

/// 对齐 procfs parseReadAheadCache：ra 行固定 12 个字段
fn parse_read_ahead_cache(values: &[u64]) -> Result<[u64; 12], CollectorError> {
    if values.len() != 12 {
        return Err(parse_error(format!(
            "invalid ReadAheadCache line {values:?}"
        )));
    }
    let mut read_ahead_cache = [0u64; 12];
    read_ahead_cache.copy_from_slice(values);
    Ok(read_ahead_cache)
}

/// 对齐 procfs parseServerRPC：rpc 行固定 5 个字段
fn parse_server_rpc(values: &[u64]) -> Result<[u64; 5], CollectorError> {
    if values.len() != 5 {
        return Err(parse_error(format!("invalid RPC line {values:?}")));
    }
    let mut server_rpc = [0u64; 5];
    server_rpc.copy_from_slice(values);
    Ok(server_rpc)
}

/// 对齐 procfs parseServerV4Stats：proc4 行须恰为 2 个方法
fn parse_server_v4(values: &[u64]) -> Result<[u64; 2], CollectorError> {
    let count = values[0] as usize;
    if values.len() - 1 != count || count != 2 {
        return Err(parse_error(format!("invalid V4Stats line {values:?}")));
    }
    let mut v4 = [0u64; 2];
    v4.copy_from_slice(&values[1..]);
    Ok(v4)
}

/// 对齐 procfs parseV4Ops：至少 39 个方法；values > 39 时 RelLockOwner 取 v[40]
fn parse_v4_ops(values: &[u64]) -> Result<V4Ops, CollectorError> {
    let count = values[0] as usize;
    if values.len() - 1 != count || count < 39 {
        return Err(parse_error(format!("invalid V4Ops line {values:?}")));
    }
    let mut v4_ops = V4Ops {
        values: [0u64; 39],
        rel_lock_owner: if count > 39 { values[40] } else { 0 },
    };
    for (slot, value) in v4_ops.values.iter_mut().zip(&values[1..]) {
        *slot = *value;
    }
    Ok(v4_ops)
}

/// 解析 /proc/net/rpc/nfsd 全文（对齐 procfs ParseServerRPCStats 的逐行分发；
/// th 行仅取前 2 个数值，忽略后面的耗时直方图）
fn parse_server_rpc_stats(content: &str) -> Result<ServerRpcStats, CollectorError> {
    let mut stats = ServerRpcStats::default();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 至少要求 <key> <value>（对齐 Go：len(parts) < 2 报错）
        if fields.len() < 2 {
            return Err(parse_error(format!("invalid NFSd metric line {line:?}")));
        }
        let prefix = "error parsing NFSd metric line";
        let values = if fields[0] == "th" {
            if fields.len() < 3 {
                return Err(parse_error(format!("invalid NFSd th metric line {line:?}")));
            }
            parse_uint64s(&fields[1..3], prefix)?
        } else {
            parse_uint64s(&fields[1..], prefix)?
        };
        match fields[0] {
            "rc" => stats.reply_cache = parse_reply_cache(&values)?,
            "fh" => stats.file_handles = parse_file_handles(&values)?,
            "io" => stats.input_output = parse_input_output(&values)?,
            "th" => stats.threads = parse_threads(&values)?,
            "ra" => stats.read_ahead_cache = parse_read_ahead_cache(&values)?,
            "net" => stats.network = parse_network(&values, NFSD_FILE)?,
            "rpc" => stats.server_rpc = parse_server_rpc(&values)?,
            "proc2" => {
                let methods = parse_proc_stats(&values, 18, "V2Stats", NFSD_FILE)?;
                for (slot, value) in stats.v2.iter_mut().zip(methods) {
                    *slot = value;
                }
            }
            "proc3" => {
                let methods = parse_proc_stats(&values, 22, "V3Stats", NFSD_FILE)?;
                for (slot, value) in stats.v3.iter_mut().zip(methods) {
                    *slot = value;
                }
            }
            "proc4" => stats.v4 = parse_server_v4(&values)?,
            "proc4ops" => stats.v4_ops = parse_v4_ops(&values)?,
            "wdeleg_getattr" => stats.wdeleg_getattr = values[0],
            unknown => return Err(parse_error(format!("unknown NFSd metric line {unknown:?}"))),
        }
    }
    Ok(stats)
}

/// 按 (method, 索引) 清单推送 requests 样本
fn push_method_stats(
    family: &mut MetricFamily,
    proto: &str,
    methods: &[(&str, usize)],
    values: &[u64],
) {
    for (method, index) in methods {
        family.push_labeled(
            vec![
                ("proto".to_string(), proto.to_string()),
                ("method".to_string(), (*method).to_string()),
            ],
            values[*index] as f64,
        );
    }
}

pub struct NfsdCollector {
    proc_path: PathBuf,
}

impl NfsdCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for NfsdCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for NfsdCollector {
    fn name(&self) -> &'static str {
        "nfsd"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let nfsd_path = self.proc_path.join(NFSD_FILE);
        let content = match std::fs::read_to_string(&nfsd_path) {
            Ok(content) => content,
            // 统计文件缺失（NFSd 未启用）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let stats = parse_server_rpc_stats(&content)?;

        let mut reply_cache_hits = MetricFamily::new(
            "node_nfsd_reply_cache_hits_total",
            "Total number of NFSd Reply Cache hits (client lost server response).",
            MetricType::Counter,
        );
        reply_cache_hits.push(stats.reply_cache[0] as f64);
        let mut reply_cache_misses = MetricFamily::new(
            "node_nfsd_reply_cache_misses_total",
            "Total number of NFSd Reply Cache an operation that requires caching (idempotent).",
            MetricType::Counter,
        );
        reply_cache_misses.push(stats.reply_cache[1] as f64);
        let mut reply_cache_nocache = MetricFamily::new(
            "node_nfsd_reply_cache_nocache_total",
            "Total number of NFSd Reply Cache non-idempotent operations (rename/delete/…).",
            MetricType::Counter,
        );
        reply_cache_nocache.push(stats.reply_cache[2] as f64);

        let mut file_handles_stale = MetricFamily::new(
            "node_nfsd_file_handles_stale_total",
            "Total number of NFSd stale file handles",
            MetricType::Counter,
        );
        file_handles_stale.push(stats.file_handles[0] as f64);

        let mut disk_bytes_read = MetricFamily::new(
            "node_nfsd_disk_bytes_read_total",
            "Total NFSd bytes read.",
            MetricType::Counter,
        );
        disk_bytes_read.push(stats.input_output[0] as f64);
        let mut disk_bytes_written = MetricFamily::new(
            "node_nfsd_disk_bytes_written_total",
            "Total NFSd bytes written.",
            MetricType::Counter,
        );
        disk_bytes_written.push(stats.input_output[1] as f64);

        let mut server_threads = MetricFamily::new(
            "node_nfsd_server_threads",
            "Total number of NFSd kernel threads that are running.",
            MetricType::Gauge,
        );
        server_threads.push(stats.threads[0] as f64);

        let mut read_ahead_cache_size = MetricFamily::new(
            "node_nfsd_read_ahead_cache_size_blocks",
            "How large the read ahead cache is in blocks.",
            MetricType::Gauge,
        );
        read_ahead_cache_size.push(stats.read_ahead_cache[0] as f64);
        let mut read_ahead_cache_not_found = MetricFamily::new(
            "node_nfsd_read_ahead_cache_not_found_total",
            "Total number of NFSd read ahead cache not found.",
            MetricType::Counter,
        );
        read_ahead_cache_not_found.push(stats.read_ahead_cache[11] as f64);

        let mut packets = MetricFamily::new(
            "node_nfsd_packets_total",
            "Total NFSd network packets (sent+received) by protocol type.",
            MetricType::Counter,
        );
        packets.push_labeled(
            vec![("proto".to_string(), "udp".to_string())],
            stats.network[1] as f64,
        );
        packets.push_labeled(
            vec![("proto".to_string(), "tcp".to_string())],
            stats.network[2] as f64,
        );

        let mut connections = MetricFamily::new(
            "node_nfsd_connections_total",
            "Total number of NFSd TCP connections.",
            MetricType::Counter,
        );
        connections.push(stats.network[3] as f64);

        let mut rpc_errors = MetricFamily::new(
            "node_nfsd_rpc_errors_total",
            "Total number of NFSd RPC errors by error type.",
            MetricType::Counter,
        );
        rpc_errors.push_labeled(
            vec![("error".to_string(), "fmt".to_string())],
            stats.server_rpc[2] as f64,
        );
        rpc_errors.push_labeled(
            vec![("error".to_string(), "auth".to_string())],
            stats.server_rpc[3] as f64,
        );
        rpc_errors.push_labeled(
            vec![("error".to_string(), "cInt".to_string())],
            stats.server_rpc[4] as f64,
        );

        let mut server_rpcs = MetricFamily::new(
            "node_nfsd_server_rpcs_total",
            "Total number of NFSd RPCs.",
            MetricType::Counter,
        );
        server_rpcs.push(stats.server_rpc[0] as f64);

        let mut requests = MetricFamily::new(
            "node_nfsd_requests_total",
            "Total number NFSd Requests by method and protocol.",
            MetricType::Counter,
        );
        push_method_stats(&mut requests, "2", &NFSD_V2_METHODS, &stats.v2);
        push_method_stats(&mut requests, "3", &NFSD_V3_METHODS, &stats.v3);
        push_method_stats(&mut requests, "4", &V4OPS_METHODS, &stats.v4_ops.values);
        // RelLockOwner 取自 proc4ops 第 40 个方法（旧内核不足时为 0）
        requests.push_labeled(
            vec![
                ("proto".to_string(), "4".to_string()),
                ("method".to_string(), "RelLockOwner".to_string()),
            ],
            stats.v4_ops.rel_lock_owner as f64,
        );
        // wdeleg_getattr 以 proto=4/method=WdelegGetattr 输出
        requests.push_labeled(
            vec![
                ("proto".to_string(), "4".to_string()),
                ("method".to_string(), "WdelegGetattr".to_string()),
            ],
            stats.wdeleg_getattr as f64,
        );

        Ok(vec![
            reply_cache_hits,
            reply_cache_misses,
            reply_cache_nocache,
            file_handles_stale,
            disk_bytes_read,
            disk_bytes_written,
            server_threads,
            read_ahead_cache_size,
            read_ahead_cache_not_found,
            packets,
            connections,
            rpc_errors,
            server_rpcs,
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

    /// 对齐 e2e-output.txt 的 node_nfsd 段黄金期望（fixture 与上游一致）
    #[test]
    fn test_collect_matches_fixture() {
        let collector = NfsdCollector::with_root(fixture_proc());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 14);

        // reply cache
        assert_eq!(families[0].name, "node_nfsd_reply_cache_hits_total");
        assert_eq!(families[0].samples[0].value, 0.0);
        assert_eq!(families[1].samples[0].value, 6.0);
        assert_eq!(families[2].samples[0].value, 18_622.0);

        // file handles / io / threads / read ahead
        assert_eq!(families[3].samples[0].value, 0.0);
        assert_eq!(families[4].samples[0].value, 157_286_400.0);
        assert_eq!(families[5].samples[0].value, 72_864.0);
        assert_eq!(families[6].name, "node_nfsd_server_threads");
        assert_eq!(families[6].samples[0].value, 8.0);
        assert_eq!(families[7].samples[0].value, 32.0);
        assert_eq!(families[8].samples[0].value, 0.0);

        // network / server rpc
        assert_eq!(value_of(&families[9], &[("proto", "udp")]), 55.0);
        assert_eq!(value_of(&families[9], &[("proto", "tcp")]), 917.0);
        assert_eq!(families[10].samples[0].value, 1.0);
        assert_eq!(value_of(&families[11], &[("error", "fmt")]), 1.0);
        assert_eq!(value_of(&families[11], &[("error", "auth")]), 2.0);
        assert_eq!(value_of(&families[11], &[("error", "cInt")]), 0.0);
        assert_eq!(families[12].samples[0].value, 18_628.0);

        // requests：17 + 21 + 36 = 74 个样本
        assert_eq!(families[13].name, "node_nfsd_requests_total");
        assert_eq!(families[13].samples.len(), 74);

        // proto2 抽查（无 Null）
        assert_eq!(request_of(&families[13], "2", "GetAttr"), 69.0);
        assert_eq!(request_of(&families[13], "2", "Lookup"), 4410.0);
        assert_eq!(request_of(&families[13], "2", "ReadDir"), 99.0);
        assert_eq!(request_of(&families[13], "2", "FsStat"), 2.0);

        // proto3 抽查（无 Null）
        assert_eq!(request_of(&families[13], "3", "GetAttr"), 112.0);
        assert_eq!(request_of(&families[13], "3", "Access"), 111.0);
        assert_eq!(request_of(&families[13], "3", "ReadDirPlus"), 216.0);
        assert_eq!(request_of(&families[13], "3", "PathConf"), 1.0);

        // proto4ops 抽查 + RelLockOwner + WdelegGetattr
        assert_eq!(request_of(&families[13], "4", "Access"), 1098.0);
        assert_eq!(request_of(&families[13], "4", "GetAttr"), 8179.0);
        assert_eq!(request_of(&families[13], "4", "GetFH"), 5896.0);
        assert_eq!(request_of(&families[13], "4", "Lookup"), 5900.0);
        assert_eq!(request_of(&families[13], "4", "PutFH"), 9609.0);
        assert_eq!(request_of(&families[13], "4", "Read"), 150.0);
        assert_eq!(request_of(&families[13], "4", "ReadDir"), 1272.0);
        assert_eq!(request_of(&families[13], "4", "Renew"), 1236.0);
        assert_eq!(request_of(&families[13], "4", "RelLockOwner"), 0.0);
        assert_eq!(request_of(&families[13], "4", "WdelegGetattr"), 15.0);
    }

    /// 文件缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_file_yields_empty() {
        let collector = NfsdCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    /// 对齐 ParseServerRPCStats 的错误语义：行字段不足、th 行字段不足、
    /// 非法数值、未知 key
    #[test]
    fn test_parse_errors() {
        // len(parts) < 2
        assert!(matches!(
            parse_server_rpc_stats("rc"),
            Err(CollectorError::Parse { .. })
        ));
        // th 行字段数 < 3
        assert!(matches!(
            parse_server_rpc_stats("th 8"),
            Err(CollectorError::Parse { .. })
        ));
        // th 行的耗时直方图含浮点不参与解析（仅取前 2 个数值）
        let stats = parse_server_rpc_stats("th 8 0 0.000 0.000")
            .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.threads, [8, 0]);
        // 非法数值
        assert!(matches!(
            parse_server_rpc_stats("rc -1 2 3"),
            Err(CollectorError::Parse { .. })
        ));
        // 未知 key
        assert!(matches!(
            parse_server_rpc_stats("bogus 1 2"),
            Err(CollectorError::Parse { .. })
        ));
        // rc 行字段数不为 3
        assert!(matches!(
            parse_server_rpc_stats("rc 1 2"),
            Err(CollectorError::Parse { .. })
        ));
        // fh 行字段数不为 5
        assert!(matches!(
            parse_server_rpc_stats("fh 1 2 3 4"),
            Err(CollectorError::Parse { .. })
        ));
        // io 行字段数不为 2
        assert!(matches!(
            parse_server_rpc_stats("io 1 2 3"),
            Err(CollectorError::Parse { .. })
        ));
        // ra 行字段数不为 12
        assert!(matches!(
            parse_server_rpc_stats("ra 1 2 3 4 5 6 7 8 9 10 11"),
            Err(CollectorError::Parse { .. })
        ));
        // proc4 行方法数不为 2
        assert!(matches!(
            parse_server_rpc_stats("proc4 3 2 10853"),
            Err(CollectorError::Parse { .. })
        ));
        // proc4ops 行方法数 < 39
        assert!(matches!(
            parse_server_rpc_stats(
                "proc4ops 38 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1"
            ),
            Err(CollectorError::Parse { .. })
        ));
    }

    /// proc4ops 恰为 39 个方法时 RelLockOwner 补 0（对齐 parseV4Ops 的 v40 语义）
    #[test]
    fn test_parse_v4_ops_rel_lock_owner() {
        let stats = parse_server_rpc_stats(
            "proc4ops 39 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3",
        )
        .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.v4_ops.values[0], 1);
        assert_eq!(stats.v4_ops.values[38], 3);
        assert_eq!(stats.v4_ops.rel_lock_owner, 0);
        // 40 个方法时 RelLockOwner 取第 40 个方法值
        let stats = parse_server_rpc_stats(
            "proc4ops 40 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7 8 9 1 2 3 99",
        )
        .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.v4_ops.rel_lock_owner, 99);
    }
}
