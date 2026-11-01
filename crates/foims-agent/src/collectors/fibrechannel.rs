//! fibrechannel 采集器：FibreChannel 主机统计。
//!
//! 对齐 node_exporter `fibrechannel_linux.go`（默认启用）与 procfs sysfs
//! FibreChannelClass（v0.23.0）：遍历 /sys/class/fc_host/ 全部条目，输出：
//! - `node_fibrechannel_info`（Gauge，值恒 1）：标签 fc_host/speed/port_state/
//!   port_type/port_id/port_name/fabric_name/symbolic_name/supported_classes/
//!   supported_speeds/dev_loss_tmo；属性文件缺失记空串（对齐 Go
//!   SafeDereference）；port_id/port_name/fabric_name 剥离 "0x" 前缀（对齐
//!   sysfs 读取后剥前 2 字符）；node_name 参与读取但不输出（对齐 Go）；
//! - 14 个 Counter（statistics/ 下计数文件，按 Go pushCounter 推送序）：
//!   dumped_frames_total、error_frames_total、invalid_crc_total、
//!   rx_frames_total、rx_words_total、tx_frames_total、tx_words_total、
//!   seconds_since_last_reset_total、invalid_tx_words_total、
//!   link_failure_total、loss_of_sync_total、loss_of_signal_total、
//!   nos_total、fcp_packet_aborts_total；statistics 目录缺失按 0 输出；
//!   值等于 u64::MAX 视为固件未实现，不输出该样本（对齐 pushCounter）。
//!
//! 偏离点：
//! - fc_host 目录缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - host 按目录名字典序输出（Go map 遍历无序，仅为输出稳定性）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// FibreChannel 主机目录（相对 sys_path）
const FC_HOST_DIR: &str = "class/fc_host";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;
/// HBA 固件未实现计数器的哨兵值（等于该值的 counter 不输出）
const UNIMPLEMENTED_COUNTER: u64 = u64::MAX;

/// info 属性的 sysfs 文件清单（对齐 Go parseFibreChannelHost 的读取顺序，
/// node_name 不参与输出但保留读取以对齐错误行为）
const INFO_FILES: [&str; 11] = [
    "speed",
    "port_state",
    "port_type",
    "node_name",
    "port_id",
    "port_name",
    "fabric_name",
    "dev_loss_tmo",
    "symbolic_name",
    "supported_classes",
    "supported_speeds",
];

/// counter 指标清单：(statistics/ 文件名, 指标名, help)，按 Go pushCounter 推送序
const COUNTER_METRICS: [(&str, &str, &str); 14] = [
    (
        "dumped_frames",
        "node_fibrechannel_dumped_frames_total",
        "Number of dumped frames",
    ),
    (
        "error_frames",
        "node_fibrechannel_error_frames_total",
        "Number of errors in frames",
    ),
    (
        "invalid_crc_count",
        "node_fibrechannel_invalid_crc_total",
        "Invalid Cyclic Redundancy Check count",
    ),
    (
        "rx_frames",
        "node_fibrechannel_rx_frames_total",
        "Number of frames received",
    ),
    (
        "rx_words",
        "node_fibrechannel_rx_words_total",
        "Number of words received by host port",
    ),
    (
        "tx_frames",
        "node_fibrechannel_tx_frames_total",
        "Number of frames transmitted by host port",
    ),
    (
        "tx_words",
        "node_fibrechannel_tx_words_total",
        "Number of words transmitted by host port",
    ),
    (
        "seconds_since_last_reset",
        "node_fibrechannel_seconds_since_last_reset_total",
        "Number of seconds since last host port reset",
    ),
    (
        "invalid_tx_word_count",
        "node_fibrechannel_invalid_tx_words_total",
        "Number of invalid words transmitted by host port",
    ),
    (
        "link_failure_count",
        "node_fibrechannel_link_failure_total",
        "Number of times the host port link has failed",
    ),
    (
        "loss_of_sync_count",
        "node_fibrechannel_loss_of_sync_total",
        "Number of failures on either bit or transmission word boundaries",
    ),
    (
        "loss_of_signal_count",
        "node_fibrechannel_loss_of_signal_total",
        "Number of times signal has been lost",
    ),
    (
        "nos_count",
        "node_fibrechannel_nos_total",
        "Number Not_Operational Primitive Sequence received by host port",
    ),
    (
        "fcp_packet_aborts",
        "node_fibrechannel_fcp_packet_aborts_total",
        "Number of aborted packets",
    ),
];

pub struct FibreChannelCollector {
    sys_path: PathBuf,
}

impl FibreChannelCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for FibreChannelCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: FC_HOST_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
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

/// info 标签值：属性缺失 → 空串（对齐 SafeDereference）；strip 时剥前 2 字符
fn label_of(value: &Option<String>, strip: bool) -> String {
    match value {
        Some(value) if strip => strip_prefix_2(value),
        Some(value) => value.clone(),
        None => String::new(),
    }
}

/// 剥离 sysfs 值的前 2 字节（对齐 Go `value[2:]`，用于去 "0x" 前缀）
fn strip_prefix_2(value: &str) -> String {
    if value.len() > 2 {
        String::from_utf8_lossy(&value.as_bytes()[2..]).into_owned()
    } else {
        value.to_string()
    }
}

/// 读取单个 info 属性（文件缺失 → None，其余读取错误传播，对齐 Go）
fn read_info(host_path: &Path, file: &str) -> Result<Option<String>, CollectorError> {
    match sys_read_file(&host_path.join(file)) {
        Ok(value) => Ok(Some(value)),
        Err(CollectorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// 读取单个 host 的 statistics/ 计数（对齐 Go parseFibreChannelStatistics：
/// 目录缺失 → 全 None；跳过非常规文件与 reset_statistics；读取失败按
/// NotFound/Unsupported/InvalidInput 跳过，其余报错；已知计数文件解析失败
/// 报错，未知文件忽略）
fn read_statistics(host_path: &Path) -> Result<[Option<u64>; 14], CollectorError> {
    let mut counters = [None; 14];
    // statistics 目录缺失 → 全部按 0 输出（对齐 Go IsNotExist）
    let entries = match std::fs::read_dir(host_path.join("statistics")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(counters),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        // 对齐 Go：仅常规文件参与，跳过 write-only 的 reset_statistics
        if !entry.file_type()?.is_file() || name == std::ffi::OsStr::new("reset_statistics") {
            continue;
        }
        let path = entry.path();
        let value = match sys_read_file(&path) {
            Ok(value) => value,
            // 对齐 Go：write-only 文件读取失败可安全跳过
            Err(CollectorError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::InvalidInput
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(field) = name.into_string().ok() else {
            continue;
        };
        let Some(position) = COUNTER_METRICS
            .iter()
            .position(|(file, _, _)| *file == field)
        else {
            continue;
        };
        counters[position] =
            Some(
                parse_uint_base0(&value).map_err(|error| CollectorError::Parse {
                    file: FC_HOST_DIR,
                    reason: format!("{} 值非法: {error}", path.display()),
                })?,
            );
    }
    Ok(counters)
}

impl Collector for FibreChannelCollector {
    fn name(&self) -> &'static str {
        "fibrechannel"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let host_dir = self.sys_path.join(FC_HOST_DIR);
        let mut host_paths: Vec<PathBuf> = match std::fs::read_dir(&host_dir) {
            // 对齐 Go：不过滤条目，读取属性失败（含非目录条目）按错误处理
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect(),
            // fc_host 目录缺失（无 FC 适配器）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        host_paths.sort();

        let mut info = MetricFamily::new(
            "node_fibrechannel_info",
            "Non-numeric data from /sys/class/fc_host/<host>, value is always 1.",
            MetricType::Gauge,
        );
        let mut counters: Vec<MetricFamily> = COUNTER_METRICS
            .iter()
            .map(|(_, name, help)| MetricFamily::new(name, help, MetricType::Counter))
            .collect();

        for host_path in host_paths {
            let Some(host) = host_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            // 先读 info 属性（对齐 Go parseFibreChannelHost）
            let mut values: [Option<String>; 11] = Default::default();
            for (index, file) in INFO_FILES.iter().enumerate() {
                values[index] = read_info(&host_path, file)?;
            }
            // 标签序对齐 Go infoDesc：node_name（values[3]）不输出
            info.push_labeled(
                vec![
                    ("fc_host".to_string(), host.to_string()),
                    ("speed".to_string(), label_of(&values[0], false)),
                    ("port_state".to_string(), label_of(&values[1], false)),
                    ("port_type".to_string(), label_of(&values[2], false)),
                    ("port_id".to_string(), label_of(&values[4], true)),
                    ("port_name".to_string(), label_of(&values[5], true)),
                    ("fabric_name".to_string(), label_of(&values[6], true)),
                    ("symbolic_name".to_string(), label_of(&values[8], false)),
                    ("supported_classes".to_string(), label_of(&values[9], false)),
                    ("supported_speeds".to_string(), label_of(&values[10], false)),
                    ("dev_loss_tmo".to_string(), label_of(&values[7], false)),
                ],
                1.0,
            );

            // 再推 counters（statistics 缺失 → 全 None → 按 0 输出）
            let statistics = read_statistics(&host_path)?;
            let host_label = vec![("fc_host".to_string(), host.to_string())];
            for (position, family) in counters.iter_mut().enumerate() {
                match statistics[position] {
                    // 未实现计数器（固件哨兵值）不输出
                    Some(UNIMPLEMENTED_COUNTER) => {}
                    Some(value) => family.push_labeled(host_label.clone(), value as f64),
                    None => family.push_labeled(host_label.clone(), 0.0),
                }
            }
        }

        let mut families = vec![info];
        families.extend(counters);
        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
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

    #[test]
    fn test_collect_matches_fixture() {
        let collector = FibreChannelCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 15);

        // info 族：三个 host
        assert_eq!(families[0].name, "node_fibrechannel_info");
        assert_eq!(families[0].samples.len(), 3);
        // host0 全量属性（port_id/port_name/fabric_name 剥 0x 前缀）
        assert_eq!(
            value_of(
                &families[0],
                &[
                    ("fc_host", "host0"),
                    ("speed", "16 Gbit"),
                    ("port_state", "Online"),
                    ("port_type", "Point-To-Point (direct nport connection)"),
                    ("port_id", "000002"),
                    ("port_name", "1000e0071bce95f2"),
                    ("fabric_name", "0"),
                    (
                        "symbolic_name",
                        "Emulex SN1100E2P FV12.4.270.3 DV12.4.0.0. HN:gotest. OS:Linux"
                    ),
                    ("supported_classes", "Class 3"),
                    ("supported_speeds", "4 Gbit, 8 Gbit, 16 Gbit"),
                    ("dev_loss_tmo", "30"),
                ]
            ),
            1.0
        );
        // host1 仅 speed/port_state，其余属性缺失 → 空串
        assert_eq!(
            value_of(
                &families[0],
                &[
                    ("fc_host", "host1"),
                    ("speed", "8 Gbit"),
                    ("port_state", "Online"),
                    ("port_type", ""),
                    ("port_id", ""),
                    ("port_name", ""),
                    ("fabric_name", ""),
                    ("symbolic_name", ""),
                    ("supported_classes", ""),
                    ("supported_speeds", ""),
                    ("dev_loss_tmo", ""),
                ]
            ),
            1.0
        );
        // host2 全量属性但 symbolic_name/supported_speeds 缺失 → 空串
        assert_eq!(
            value_of(
                &families[0],
                &[
                    ("fc_host", "host2"),
                    ("speed", "unknown"),
                    ("port_state", "Online"),
                    ("port_type", "NPIV VPORT"),
                    ("port_id", "0b19e2"),
                    ("port_name", "c050760aab8f2cff"),
                    ("fabric_name", "c050760aab8f2cff"),
                    ("symbolic_name", ""),
                    ("supported_classes", "Class 3"),
                    ("supported_speeds", ""),
                    ("dev_loss_tmo", "300"),
                ]
            ),
            1.0
        );

        // counter 族：host0 的 dumped_frames = u64::MAX → 不输出
        assert_eq!(families[1].name, "node_fibrechannel_dumped_frames_total");
        assert_eq!(families[1].samples.len(), 2);
        assert_eq!(value_of(&families[1], &[("fc_host", "host1")]), 0.0);
        assert_eq!(value_of(&families[1], &[("fc_host", "host2")]), 0.0);
        // host1 的 fcp_packet_aborts = u64::MAX → 不输出
        assert_eq!(
            families[14].name,
            "node_fibrechannel_fcp_packet_aborts_total"
        );
        assert_eq!(families[14].samples.len(), 2);
        assert_eq!(value_of(&families[14], &[("fc_host", "host0")]), 19.0);
        assert_eq!(value_of(&families[14], &[("fc_host", "host2")]), 0.0);

        // host0 十六进制计数（0x2=2、0x10=16 等）
        assert_eq!(value_of(&families[2], &[("fc_host", "host0")]), 0.0);
        assert_eq!(value_of(&families[3], &[("fc_host", "host0")]), 2.0);
        assert_eq!(value_of(&families[4], &[("fc_host", "host0")]), 3.0);
        assert_eq!(value_of(&families[5], &[("fc_host", "host0")]), 4.0);
        assert_eq!(value_of(&families[6], &[("fc_host", "host0")]), 5.0);
        assert_eq!(value_of(&families[7], &[("fc_host", "host0")]), 6.0);
        assert_eq!(value_of(&families[8], &[("fc_host", "host0")]), 7.0);
        assert_eq!(value_of(&families[9], &[("fc_host", "host0")]), 8.0);
        assert_eq!(value_of(&families[10], &[("fc_host", "host0")]), 9.0);
        assert_eq!(value_of(&families[11], &[("fc_host", "host0")]), 16.0);
        assert_eq!(value_of(&families[12], &[("fc_host", "host0")]), 17.0);
        assert_eq!(value_of(&families[13], &[("fc_host", "host0")]), 18.0);
        // host1 计数
        assert_eq!(value_of(&families[2], &[("fc_host", "host1")]), 19.0);
        assert_eq!(value_of(&families[3], &[("fc_host", "host1")]), 32.0);
        assert_eq!(value_of(&families[13], &[("fc_host", "host1")]), 288.0);
        // host2 无 statistics → 全部按 0 输出
        assert_eq!(value_of(&families[5], &[("fc_host", "host2")]), 0.0);
        // 除 dumped/fcp_packet_aborts 外的 counter 族均有 3 个 host 样本
        for family in &families[2..14] {
            assert_eq!(family.samples.len(), 3, "{}", family.name);
        }
    }

    #[test]
    fn test_missing_fc_host_dir_yields_empty() {
        let collector = FibreChannelCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    #[test]
    fn test_parse_uint_base0() {
        assert_eq!(
            parse_uint_base0("0").unwrap_or_else(|e| panic!("解析失败: {e}")),
            0
        );
        assert_eq!(
            parse_uint_base0("12").unwrap_or_else(|e| panic!("解析失败: {e}")),
            12
        );
        assert_eq!(
            parse_uint_base0("0xffffffffffffffff").unwrap_or_else(|e| panic!("解析失败: {e}")),
            u64::MAX
        );
        assert!(parse_uint_base0("").is_err());
        assert!(parse_uint_base0("x1").is_err());
    }

    #[test]
    fn test_strip_prefix_2() {
        assert_eq!(strip_prefix_2("0x000002"), "000002");
        assert_eq!(strip_prefix_2("0x0"), "0");
        assert_eq!(strip_prefix_2("0x"), "0x");
        assert_eq!(strip_prefix_2("x"), "x");
    }
}
