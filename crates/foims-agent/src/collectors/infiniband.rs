//! infiniband 采集器：InfiniBand 设备与端口指标。
//!
//! 对齐 node_exporter `infiniband_linux.go`（默认启用）与 procfs sysfs
//! InfiniBandClass（v0.23.0）：遍历 /sys/class/infiniband/，读取设备属性
//! （fw_ver 必需，board_id/hca_type/node_guid 可选）与每个端口
//! （ports/<N>，端口名须为纯数字）的 state/phys_state/rate/link_layer 及
//! counters/、counters_ext/、hw_counters/ 计数目录，输出子系统 infiniband
//! 的 64 个指标族：
//! - `node_infiniband_info`（Gauge，值恒 1，标签 device/board_id/
//!   firmware_version/hca_type）；
//! - `node_infiniband_state_id` / `physical_state_id`（"4: ACTIVE" 格式按
//!   ':' 拆分取 ID，Gauge）与 `rate_bytes_per_second`（"40 Gb/sec" 前缀
//!   数值 × 125000000 转字节/秒，Gauge）；
//! - 8 个 legacy 计数（counters_ext/，pre-kernel-v4.5 64 位计数器）与
//!   22 个主计数（counters/），Counter 类型；
//! - 30 个 hw_counters/ 计数（Counter；lifespan_seconds 为 Gauge，毫秒
//!   值 ÷1000 转秒）。
//!
//! 数据计数文件 port_rcv_data/port_xmit_data/port_rcv_data_64/
//! port_xmit_data_64 按每端口 4 lane 乘 4（对齐 Go，回绕乘法）；计数值为
//! "N/A (no PMA)" 时跳过（node_exporter#966 兼容）。
//!
//! 偏离点：
//! - 未移植 --collector.infiniband.device-include/device-exclude 过滤参数；
//! - 设备按名字典序、端口按端口号排序输出（Go map 遍历无序）；
//! - class/infiniband 目录缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - 计数文件读取错误的跳过集合统一为 NotFound/PermissionDenied/
//!   Unsupported/InvalidInput（Go 各目录的 ErrInvalid/EINVAL 集合略有差异）；
//! - link_layer/state/phys_state 的字符串表示解析后不输出（Go 同样不输出，
//!   仅保留读取与解析校验）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// InfiniBand 设备目录（相对 sys_path）
const INFINIBAND_DIR: &str = "class/infiniband";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;
/// 计数值为 "N/A (no PMA)" 时跳过（node_exporter#966）
const NO_PMA: &str = "N/A (no PMA)";
/// 端口状态文件中 hw_counters 表内唯一的 Gauge 指标（毫秒 → 秒）
const LIFESPAN_METRIC: &str = "lifespan_seconds";

pub struct InfinibandCollector {
    sys_path: PathBuf,
}

impl InfinibandCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for InfinibandCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// InfiniBand 端口（对应 procfs InfiniBandPort，仅保留输出字段）
#[derive(Debug)]
struct InfiniBandPort {
    port: u32,
    state_id: u32,
    physical_state_id: u32,
    /// 字节/秒（"40 Gb/sec" 前缀数值 × 125000000）
    rate: u64,
    /// counters/ + counters_ext/ 计数（键为指标名）
    counters: HashMap<String, u64>,
    /// hw_counters/ 计数（键为指标名）
    hw_counters: HashMap<String, u64>,
}

/// InfiniBand 设备（对应 procfs InfiniBandDevice，仅保留输出字段）
#[derive(Debug)]
struct InfiniBandDevice {
    name: String,
    board_id: String,
    firmware_version: String,
    hca_type: String,
    /// 已按端口号排序
    ports: Vec<InfiniBandPort>,
}

/// counters/ 与 counters_ext/ 计数文件 → 指标映射（顺序对齐 Go Update
/// 推送序）：（指标名，sysfs 文件名，是否为 ×4 数据计数，help）
const COUNTER_METRICS: [(&str, &str, bool, &str); 30] = [
    // legacy 组（counters_ext/，pre-kernel-v4.5 64 位计数器）
    (
        "legacy_multicast_packets_received_total",
        "port_multicast_rcv_packets",
        false,
        "Number of multicast packets received",
    ),
    (
        "legacy_multicast_packets_transmitted_total",
        "port_multicast_xmit_packets",
        false,
        "Number of multicast packets transmitted",
    ),
    (
        "legacy_data_received_bytes_total",
        "port_rcv_data_64",
        true,
        "Number of data octets received on all links",
    ),
    (
        "legacy_packets_received_total",
        "port_rcv_packets_64",
        false,
        "Number of data packets received on all links",
    ),
    (
        "legacy_unicast_packets_received_total",
        "port_unicast_rcv_packets",
        false,
        "Number of unicast packets received",
    ),
    (
        "legacy_unicast_packets_transmitted_total",
        "port_unicast_xmit_packets",
        false,
        "Number of unicast packets transmitted",
    ),
    (
        "legacy_data_transmitted_bytes_total",
        "port_xmit_data_64",
        true,
        "Number of data octets transmitted on all links",
    ),
    // 对齐 Go：help 文本原文即 "received"（上游笔误保留）
    (
        "legacy_packets_transmitted_total",
        "port_xmit_packets_64",
        false,
        "Number of data packets received on all links",
    ),
    // 主组（counters/）
    (
        "excessive_buffer_overrun_errors_total",
        "excessive_buffer_overrun_errors",
        false,
        "Number of times that OverrunErrors consecutive flow control update periods occurred, each having at least one overrun error.",
    ),
    (
        "link_downed_total",
        "link_downed",
        false,
        "Number of times the link failed to recover from an error state and went down",
    ),
    (
        "link_error_recovery_total",
        "link_error_recovery",
        false,
        "Number of times the link successfully recovered from an error state",
    ),
    (
        "local_link_integrity_errors_total",
        "local_link_integrity_errors",
        false,
        "Number of times that the count of local physical errors exceeded the threshold specified by LocalPhyErrors.",
    ),
    (
        "multicast_packets_received_total",
        "multicast_rcv_packets",
        false,
        "Number of multicast packets received (including errors)",
    ),
    (
        "multicast_packets_transmitted_total",
        "multicast_xmit_packets",
        false,
        "Number of multicast packets transmitted (including errors)",
    ),
    (
        "port_constraint_errors_received_total",
        "port_rcv_constraint_errors",
        false,
        "Number of packets received on the switch physical port that are discarded",
    ),
    (
        "port_constraint_errors_transmitted_total",
        "port_xmit_constraint_errors",
        false,
        "Number of packets not transmitted from the switch physical port",
    ),
    (
        "port_data_received_bytes_total",
        "port_rcv_data",
        true,
        "Number of data octets received on all links",
    ),
    (
        "port_data_transmitted_bytes_total",
        "port_xmit_data",
        true,
        "Number of data octets transmitted on all links",
    ),
    (
        "port_discards_received_total",
        "port_rcv_discards",
        false,
        "Number of inbound packets discarded by the port because the port is down or congested",
    ),
    (
        "port_discards_transmitted_total",
        "port_xmit_discards",
        false,
        "Number of outbound packets discarded by the port because the port is down or congested",
    ),
    (
        "port_errors_received_total",
        "port_rcv_errors",
        false,
        "Number of packets containing an error that were received on this port",
    ),
    (
        "port_packets_received_total",
        "port_rcv_packets",
        false,
        "Number of packets received on all VLs by this port (including errors)",
    ),
    (
        "port_packets_transmitted_total",
        "port_xmit_packets",
        false,
        "Number of packets transmitted on all VLs from this port (including errors)",
    ),
    (
        "port_transmit_wait_total",
        "port_xmit_wait",
        false,
        "Number of ticks during which the port had data to transmit but no data was sent during the entire tick",
    ),
    (
        "unicast_packets_received_total",
        "unicast_rcv_packets",
        false,
        "Number of unicast packets received (including errors)",
    ),
    (
        "unicast_packets_transmitted_total",
        "unicast_xmit_packets",
        false,
        "Number of unicast packets transmitted (including errors)",
    ),
    (
        "port_receive_remote_physical_errors_total",
        "port_rcv_remote_physical_errors",
        false,
        "Number of packets marked with the EBP (End of Bad Packet) delimiter received on the port.",
    ),
    (
        "port_receive_switch_relay_errors_total",
        "port_rcv_switch_relay_errors",
        false,
        "Number of packets that could not be forwarded by the switch.",
    ),
    (
        "symbol_error_total",
        "symbol_error",
        false,
        "Number of minor link errors detected on one or more physical lanes.",
    ),
    (
        "vl15_dropped_total",
        "VL15_dropped",
        false,
        "Number of incoming VL15 packets dropped due to resource limitations.",
    ),
];

/// hw_counters/ 计数文件 → 指标映射（顺序对齐 Go Update 推送序；首条
/// lifespan_seconds 为 Gauge 且值 ÷1000）：（指标名，sysfs 文件名，
/// 是否 ×4（恒 false，与 counters 表共用解析函数），help）
const HW_COUNTER_METRICS: [(&str, &str, bool, &str); 30] = [
    (
        "lifespan_seconds",
        "lifespan",
        false,
        "The maximum period in ms which defines the aging of the counter reads. Two consecutive reads within this period might return the same values.",
    ),
    (
        "duplicate_requests_packets_total",
        "duplicate_request",
        false,
        "The number of received packets. A duplicate request is a request that had been previously executed.",
    ),
    (
        "implied_nak_seq_errors_total",
        "implied_nak_seq_err",
        false,
        "The number of time the requested decided an ACK. with a PSN larger than the expected PSN for an RDMA read or response.",
    ),
    (
        "local_ack_timeout_errors_total",
        "local_ack_timeout_err",
        false,
        "The number of times QP's ack timer expired for RC, XRC, DCT QPs at the sender side. The QP retry limit was not exceed, therefore it is still recoverable error.",
    ),
    (
        "np_cnp_packets_sent_total",
        "np_cnp_sent",
        false,
        "The number of CNP packets sent by the Notification Point when it noticed congestion experienced in the RoCEv2 IP header (ECN bits). The counters was added in MLNX_OFED 4.1",
    ),
    (
        "np_ecn_marked_roce_packets_received_total",
        "np_ecn_marked_roce_packets",
        false,
        "The number of RoCEv2 packets received by the notification point which were marked for experiencing the congestion (ECN bits where '11' on the ingress RoCE traffic) . The counters was added in MLNX_OFED 4.1",
    ),
    (
        "out_of_buffer_drops_total",
        "out_of_buffer",
        false,
        "The number of drops occurred due to lack of WQE for the associated QPs.",
    ),
    (
        "out_of_sequence_packets_received_total",
        "out_of_sequence",
        false,
        "The number of out of sequence packets received.",
    ),
    (
        "packet_sequence_errors_total",
        "packet_seq_err",
        false,
        "The number of received NAK sequence error packets. The QP retry limit was not exceeded.",
    ),
    (
        "req_cqes_errors_total",
        "req_cqe_error",
        false,
        "The number of times requester detected CQEs completed with errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "req_cqes_flush_errors_total",
        "req_cqe_flush_error",
        false,
        "The number of times requester detected CQEs completed with flushed errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "req_remote_access_errors_total",
        "req_remote_access_errors",
        false,
        "The number of times requester detected remote access errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "req_remote_invalid_request_errors_total",
        "req_remote_invalid_request",
        false,
        "The number of times requester detected remote invalid request errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "resp_cqes_errors_total",
        "resp_cqe_error",
        false,
        "The number of times responder detected CQEs completed with errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "resp_cqes_flush_errors_total",
        "resp_cqe_flush_error",
        false,
        "The number of times responder detected CQEs completed with flushed errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "resp_local_length_errors_total",
        "resp_local_length_error",
        false,
        "The number of times responder detected local length errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "resp_remote_access_errors_total",
        "resp_remote_access_errors",
        false,
        "The number of times responder detected remote access errors. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "rnr_nak_retry_packets_received_total",
        "rnr_nak_retry_err",
        false,
        "The number of received RNR NAK packets. The QP retry limit was not exceeded.",
    ),
    (
        "roce_adp_retransmits_total",
        "roce_adp_retrans",
        false,
        "The number of adaptive retransmissions for RoCE traffic. The counter was added in MLNX_OFED rev 5.0-1.0.0.0 and kernel v5.6.0",
    ),
    (
        "roce_adp_retransmits_timeout_total",
        "roce_adp_retrans_to",
        false,
        "The number of times RoCE traffic reached timeout due to adaptive retransmission. The counter was added in MLNX_OFED rev 5.0-1.0.0.0 and kernel v5.6.0",
    ),
    (
        "roce_slow_restart_used_total",
        "roce_slow_restart",
        false,
        "The number of times RoCE slow restart was used. The counter was added in MLNX_OFED rev 5.0-1.0.0.0 and kernel v5.6.0",
    ),
    (
        "roce_slow_restart_cnps_total",
        "roce_slow_restart_cnps",
        false,
        "The number of times RoCE slow restart generated CNP packets. The counter was added in MLNX_OFED rev 5.0-1.0.0.0 and kernel v5.6.0",
    ),
    (
        "roce_slow_restart_total",
        "roce_slow_restart_trans",
        false,
        "The number of times RoCE slow restart changed state to slow restart. The counter was added in MLNX_OFED rev 5.0-1.0.0.0 and kernel v5.6.0",
    ),
    (
        "rp_cnp_packets_handled_total",
        "rp_cnp_handled",
        false,
        "The number of CNP packets handled by the Reaction Point HCA to throttle the transmission rate. The counters was added in MLNX_OFED 4.1",
    ),
    (
        "rp_cnp_ignored_packets_received_total",
        "rp_cnp_ignored",
        false,
        "The number of CNP packets received and ignored by the Reaction Point HCA. This counter should not raise if RoCE Congestion Control was enabled in the network. If this counter raise, verify that ECN was enabled on the adapter.",
    ),
    (
        "rx_atomic_requests_total",
        "rx_atomic_requests",
        false,
        "The number of received ATOMIC request for the associated QPs.",
    ),
    (
        "rx_dct_connect_requests_total",
        "rx_dct_connect",
        false,
        "The number of received connection requests for the associated DCTs.",
    ),
    (
        "rx_icrc_encapsulated_errors_total",
        "rx_icrc_encapsulated",
        false,
        "The number of RoCE packets with ICRC errors. This counter was added in MLNX_OFED 4.4 and kernel 4.19",
    ),
    (
        "rx_read_requests_total",
        "rx_read_requests",
        false,
        "The number of received READ requests for the associated QPs.",
    ),
    (
        "rx_write_requests_total",
        "rx_write_requests",
        false,
        "The number of received WRITE requests for the associated QPs.",
    ),
];

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: INFINIBAND_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 全量读取文件（对齐 Go os.ReadFile：state/phys_state/rate/link_layer
/// 走全量读取；无效 UTF-8 以 U+FFFD 替换）
fn read_file_full(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// 对齐 Go strconv.ParseUint(s, 0, 64)：0x/0X 前缀按 16 进制，0b/0B 按
/// 2 进制，0o/0O 按 8 进制，前导 0 按 8 进制（含单个 0），其余 10 进制
fn parse_uint_base0(value: &str) -> Result<u64, std::num::ParseIntError> {
    let (digits, radix) = match value.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&value[2..], 16),
        [b'0', b'b' | b'B', ..] => (&value[2..], 2),
        [b'0', b'o' | b'O', ..] => (&value[2..], 8),
        _ => match value.strip_prefix('0') {
            Some("") => return Ok(0),
            Some(rest) => (rest, 8),
            None => (value, 10),
        },
    };
    u64::from_str_radix(digits, radix)
}

/// 解析端口状态文件（"4: ACTIVE" → 4，对齐 Go parseState；字符串表示不
/// 输出，仅校验格式）
fn parse_state_id(content: &str) -> Result<u32, CollectorError> {
    let parts: Vec<&str> = content.split(':').collect();
    if parts.len() != 2 {
        return Err(CollectorError::Parse {
            file: INFINIBAND_DIR,
            reason: format!("无法按 'ID: NAME' 拆分 {content:?}"),
        });
    }
    let id = parts[0].trim();
    id.parse::<u32>().map_err(|error| CollectorError::Parse {
        file: INFINIBAND_DIR,
        reason: format!("无法将 {id:?} 转为整数: {error}"),
    })
}

/// 解析速率文件（"40 Gb/sec (4X QDR)" → 40 × 125000000 字节/秒，对齐
/// Go parseRate）
fn parse_rate(content: &str) -> Result<u64, CollectorError> {
    let Some((value, _)) = content.split_once(' ') else {
        return Err(CollectorError::Parse {
            file: INFINIBAND_DIR,
            reason: format!("无法拆分 {content:?}"),
        });
    };
    let value: f64 = value
        .trim()
        .parse()
        .map_err(|error: std::num::ParseFloatError| CollectorError::Parse {
            file: INFINIBAND_DIR,
            reason: format!("无法将 {value:?} 转为浮点数: {error}"),
        })?;
    Ok((value * 125_000_000.0) as u64)
}

/// 读取单个计数目录（counters/counters_ext/hw_counters 通用；对齐
/// parseInfiniBandCounters：仅常规文件参与，读取失败按可跳过错误忽略，
/// 已知文件解析失败时 "N/A (no PMA)" 跳过、其余报错）
fn parse_counter_dir(
    dir: &Path,
    table: &[(&'static str, &'static str, bool, &'static str)],
) -> Result<HashMap<String, u64>, CollectorError> {
    let mut values = HashMap::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // 对齐 Go：仅常规文件参与（符号链接/目录跳过）
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let value = match sys_read_file(&path) {
            Ok(value) => value,
            // 对齐 Go：不可读计数文件（不存在/无权限/不支持/无效参数）安全跳过
            Err(CollectorError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::InvalidInput
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(file_name) = entry.file_name().into_string().ok() else {
            continue;
        };
        let Some((metric, quad)) = table
            .iter()
            .find(|(_, file, _, _)| *file == file_name)
            .map(|(metric, _, quad, _)| (*metric, *quad))
        else {
            continue;
        };
        match parse_uint_base0(&value) {
            Ok(parsed) => {
                // 数据计数按每端口 4 lane 乘 4（对齐 Go 的回绕乘法语义）
                let parsed = if quad { parsed.wrapping_mul(4) } else { parsed };
                values.insert(metric.to_string(), parsed);
            }
            Err(error) => {
                if value.contains(NO_PMA) {
                    continue;
                }
                return Err(CollectorError::Parse {
                    file: INFINIBAND_DIR,
                    reason: format!("{} 值非法: {error}", path.display()),
                });
            }
        }
    }
    Ok(values)
}

/// 解析单个端口目录（对齐 procfs parseInfiniBandPort）
fn parse_port(
    sys_path: &Path,
    device_name: &str,
    port_name: &str,
) -> Result<InfiniBandPort, CollectorError> {
    let port = port_name
        .parse::<u32>()
        .map_err(|error| CollectorError::Parse {
            file: INFINIBAND_DIR,
            reason: format!("无法将端口 {port_name:?} 转为整数: {error}"),
        })?;
    let port_path = sys_path
        .join(INFINIBAND_DIR)
        .join(device_name)
        .join("ports")
        .join(port_name);

    // 对齐 Go：link_layer 读取失败传播错误（字符串表示不输出）
    read_file_full(&port_path.join("link_layer"))?;
    let state_id = parse_state_id(&read_file_full(&port_path.join("state"))?)?;
    let physical_state_id = parse_state_id(&read_file_full(&port_path.join("phys_state"))?)?;
    let rate = parse_rate(&read_file_full(&port_path.join("rate"))?)?;

    // HCA 可能被 systemd 重命名而无法推断驱动类型，故不按命名约定假定
    // 计数目录存在：counters/ 由 os.Stat 门控（对齐 Go）
    let mut counters = HashMap::new();
    if std::fs::metadata(port_path.join("counters")).is_ok() {
        counters = parse_counter_dir(&port_path.join("counters"), &COUNTER_METRICS)?;
    }
    // counters_ext/ 为 pre-v4.5 旧式 64 位计数目录，缺失可容忍（对齐 Go）
    match parse_counter_dir(&port_path.join("counters_ext"), &COUNTER_METRICS) {
        Ok(ext) => counters.extend(ext),
        Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // hw_counters/ 目录存在才解析（对齐 Go os.Stat 门控）
    let mut hw_counters = HashMap::new();
    if std::fs::metadata(port_path.join("hw_counters")).is_ok() {
        hw_counters = parse_counter_dir(&port_path.join("hw_counters"), &HW_COUNTER_METRICS)?;
    }

    Ok(InfiniBandPort {
        port,
        state_id,
        physical_state_id,
        rate,
        counters,
        hw_counters,
    })
}

/// 解析单个设备目录（对齐 procfs parseInfiniBandDevice）
fn parse_device(sys_path: &Path, name: &str) -> Result<InfiniBandDevice, CollectorError> {
    let device_path = sys_path.join(INFINIBAND_DIR).join(name);

    // fw_ver 自内核 4.10 起所有 InfiniBand 驱动必暴露，缺失按错误处理
    let firmware_version = sys_read_file(&device_path.join("fw_ver"))?;

    // board_id/hca_type/node_guid 并非所有驱动都暴露，缺失跳过
    let mut board_id = String::new();
    let mut hca_type = String::new();
    for (file, slot) in [("board_id", &mut board_id), ("hca_type", &mut hca_type)] {
        match sys_read_file(&device_path.join(file)) {
            Ok(value) => *slot = value,
            Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    // node_guid 读取但仅校验可读性，不输出（对齐 Go）
    match sys_read_file(&device_path.join("node_guid")) {
        Ok(_) => {}
        Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // ports/ 目录缺失按错误处理（对齐 Go）
    let mut ports = Vec::new();
    for entry in std::fs::read_dir(device_path.join("ports"))? {
        let entry = entry?;
        let Some(port_name) = entry.file_name().into_string().ok() else {
            continue;
        };
        ports.push(parse_port(sys_path, name, &port_name)?);
    }
    // 端口按端口号排序输出（Go map 遍历无序）
    ports.sort_by_key(|port| port.port);

    Ok(InfiniBandDevice {
        name: name.to_string(),
        board_id,
        firmware_version,
        hca_type,
        ports,
    })
}

impl Collector for InfinibandCollector {
    fn name(&self) -> &'static str {
        "infiniband"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let ib_dir = self.sys_path.join(INFINIBAND_DIR);
        let mut device_names: Vec<String> = Vec::new();
        match std::fs::read_dir(&ib_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if let Ok(name) = entry.file_name().into_string() {
                        device_names.push(name);
                    }
                }
            }
            // class/infiniband 目录缺失（无 InfiniBand 设备）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        }
        // 设备按名字典序输出（Go map 遍历无序，仅为输出稳定性）
        device_names.sort();

        let mut devices = Vec::with_capacity(device_names.len());
        for name in device_names {
            devices.push(parse_device(&self.sys_path, &name)?);
        }

        // 预建全部 64 个指标族（顺序对齐 Go Update 推送序）
        let mut families: Vec<MetricFamily> = Vec::with_capacity(64);
        families.push(MetricFamily::new(
            "node_infiniband_info",
            "Non-numeric data from /sys/class/infiniband/<device>, value is always 1.",
            MetricType::Gauge,
        ));
        families.push(MetricFamily::new(
            "node_infiniband_state_id",
            "State of the InfiniBand port (0: no change, 1: down, 2: init, 3: armed, 4: active, 5: act defer)",
            MetricType::Gauge,
        ));
        families.push(MetricFamily::new(
            "node_infiniband_physical_state_id",
            "Physical state of the InfiniBand port (0: no change, 1: sleep, 2: polling, 3: disable, 4: shift, 5: link up, 6: link error recover, 7: phytest)",
            MetricType::Gauge,
        ));
        families.push(MetricFamily::new(
            "node_infiniband_rate_bytes_per_second",
            "Maximum signal transfer rate",
            MetricType::Gauge,
        ));
        for (metric, _, _, help) in COUNTER_METRICS {
            families.push(MetricFamily::new(
                &format!("node_infiniband_{metric}"),
                help,
                MetricType::Counter,
            ));
        }
        for (metric, _, _, help) in HW_COUNTER_METRICS {
            // hw_counters 表内 lifespan_seconds 为 Gauge，其余均为 Counter
            let mtype = if metric == LIFESPAN_METRIC {
                MetricType::Gauge
            } else {
                MetricType::Counter
            };
            families.push(MetricFamily::new(
                &format!("node_infiniband_{metric}"),
                help,
                mtype,
            ));
        }

        for device in devices {
            families[0].push_labeled(
                vec![
                    ("device".to_string(), device.name.clone()),
                    ("board_id".to_string(), device.board_id),
                    ("firmware_version".to_string(), device.firmware_version),
                    ("hca_type".to_string(), device.hca_type),
                ],
                1.0,
            );
            for port in device.ports {
                let port_str = port.port.to_string();
                let labels = || -> Vec<(String, String)> {
                    vec![
                        ("device".to_string(), device.name.clone()),
                        ("port".to_string(), port_str.clone()),
                    ]
                };
                families[1].push_labeled(labels(), port.state_id as f64);
                families[2].push_labeled(labels(), port.physical_state_id as f64);
                families[3].push_labeled(labels(), port.rate as f64);
                for (index, (metric, _, _, _)) in COUNTER_METRICS.iter().enumerate() {
                    if let Some(value) = port.counters.get(*metric) {
                        families[4 + index].push_labeled(labels(), *value as f64);
                    }
                }
                let hw_offset = 4 + COUNTER_METRICS.len();
                for (index, (metric, _, _, _)) in HW_COUNTER_METRICS.iter().enumerate() {
                    if let Some(value) = port.hw_counters.get(*metric) {
                        // lifespan（毫秒）÷1000 转秒（对齐 Go 整数除法）
                        let value = if *metric == LIFESPAN_METRIC {
                            value / 1000
                        } else {
                            *value
                        };
                        families[hw_offset + index].push_labeled(labels(), value as f64);
                    }
                }
            }
        }

        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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

    /// 按指标名定位族
    fn family_of<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|family| family.name == name)
            .unwrap_or_else(|| panic!("缺少指标族 {name}"))
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    /// 对齐 e2e-output.txt 的 infiniband 段黄金期望（fixture 值推导）
    #[test]
    fn test_collect_matches_fixture() {
        let families = InfinibandCollector::with_root(fixture_root())
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // info + 3 Gauge + 30 counters + 30 hw
        assert_eq!(families.len(), 64);

        // info：两台设备
        let info = family_of(&families, "node_infiniband_info");
        assert_eq!(info.samples.len(), 2);
        assert!(info.samples.iter().any(|sample| {
            sample.labels.len() == 4
                && sample
                    .labels
                    .contains(&("device".to_string(), "i40iw0".to_string()))
                && sample
                    .labels
                    .contains(&("board_id".to_string(), "I40IW Board ID".to_string()))
                && sample
                    .labels
                    .contains(&("firmware_version".to_string(), "0.2".to_string()))
                && sample
                    .labels
                    .contains(&("hca_type".to_string(), "I40IW".to_string()))
        }));

        // 状态与速率（i40iw0 仅 1 端口，mlx4_0 两端口）
        let state_id = family_of(&families, "node_infiniband_state_id");
        assert_eq!(state_id.samples.len(), 3);
        assert_eq!(
            value_of(state_id, &[("device", "i40iw0"), ("port", "1")]),
            4.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_physical_state_id"),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            5.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_rate_bytes_per_second"),
                &[("device", "i40iw0"), ("port", "1")]
            ),
            1_250_000_000.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_rate_bytes_per_second"),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            5_000_000_000.0
        );

        // ×4 数据计数（4631917×4 = 18527668）
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_port_data_received_bytes_total"),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            18_527_668.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_port_data_received_bytes_total"),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(
                    &families,
                    "node_infiniband_port_data_transmitted_bytes_total"
                ),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            14_933_760.0
        );
        // legacy 计数（counters_ext）
        assert_eq!(
            value_of(
                family_of(
                    &families,
                    "node_infiniband_legacy_data_received_bytes_total"
                ),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            18_527_668.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_legacy_packets_received_total"),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(
                    &families,
                    "node_infiniband_legacy_unicast_packets_transmitted_total"
                ),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            61_239.0
        );

        // 主计数（fixture 原值）
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_port_packets_received_total"),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            6_825_908_347.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_port_transmit_wait_total"),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            4_294_967_295.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_port_discards_transmitted_total"),
                &[("device", "mlx4_0"), ("port", "1")]
            ),
            5.0
        );
        assert_eq!(
            value_of(
                family_of(
                    &families,
                    "node_infiniband_multicast_packets_received_total"
                ),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_infiniband_unicast_packets_received_total"),
                &[("device", "mlx4_0"), ("port", "2")]
            ),
            0.0
        );
        // 仅 port1 有 constraint errors 计数文件
        assert_eq!(
            family_of(
                &families,
                "node_infiniband_port_constraint_errors_received_total"
            )
            .samples
            .len(),
            1
        );

        // i40iw0 计数全为 "N/A (no PMA)" → 不产生样本
        assert!(
            family_of(&families, "node_infiniband_port_data_received_bytes_total")
                .samples
                .iter()
                .all(|sample| !sample
                    .labels
                    .contains(&("device".to_string(), "i40iw0".to_string())))
        );

        // fixture 中 symbol_error/VL15_dropped 等 6 个计数文件完全缺失 → 空族
        assert!(
            family_of(&families, "node_infiniband_symbol_error_total")
                .samples
                .is_empty()
        );
        assert!(
            family_of(&families, "node_infiniband_vl15_dropped_total")
                .samples
                .is_empty()
        );
        assert!(
            family_of(
                &families,
                "node_infiniband_excessive_buffer_overrun_errors_total"
            )
            .samples
            .is_empty()
        );

        // fixture 无 hw_counters 目录 → hw 族全空
        assert!(
            family_of(&families, "node_infiniband_lifespan_seconds")
                .samples
                .is_empty()
        );
        assert!(
            family_of(&families, "node_infiniband_out_of_buffer_drops_total")
                .samples
                .is_empty()
        );
    }

    /// class/infiniband 目录缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_infiniband_dir_yields_empty() {
        let families = InfinibandCollector::with_root(PathBuf::from("/nonexistent-foims-test"))
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    /// 端口状态解析（对齐 Go parseState：恰好一个 ':'，ID 为 10 进制）
    #[test]
    fn test_parse_state_id() {
        assert_eq!(
            parse_state_id("4: ACTIVE").unwrap_or_else(|e| panic!("解析失败: {e}")),
            4
        );
        assert_eq!(
            parse_state_id("5: LinkUp\n").unwrap_or_else(|e| panic!("解析失败: {e}")),
            5
        );
        assert!(parse_state_id("invalid").is_err());
        // 多个 ':' 视为格式非法（对齐 Go Split 后长度校验）
        assert!(parse_state_id("1:2: NAME").is_err());
        assert!(parse_state_id("x: NAME").is_err());
    }

    /// 速率解析（覆盖 procfs parseRate 的代表性用例）
    #[test]
    fn test_parse_rate() {
        assert_eq!(
            parse_rate("10 Gb/sec (4X)").unwrap_or_else(|e| panic!("解析失败: {e}")),
            1_250_000_000
        );
        assert_eq!(
            parse_rate("40 Gb/sec (4X QDR)").unwrap_or_else(|e| panic!("解析失败: {e}")),
            5_000_000_000
        );
        assert_eq!(
            parse_rate("100 Gb/sec (4X EDR)").unwrap_or_else(|e| panic!("解析失败: {e}")),
            12_500_000_000
        );
        assert!(parse_rate("invalid").is_err());
        assert!(parse_rate("w invalid").is_err());
    }
}
