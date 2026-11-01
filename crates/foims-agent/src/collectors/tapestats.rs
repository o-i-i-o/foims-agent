//! tapestats 采集器：SCSI 磁带设备统计。
//!
//! 对齐 node_exporter `tapestats_linux.go`（默认启用）与 procfs sysfs
//! SCSITapeClass（v0.23.0）：遍历 /sys/class/scsi_tape/ 下名称匹配
//! `^st\d+$` 的条目（nst0/st0a 等变体排除），读取 stats/ 下 10 个计数
//! 文件，按标签 device 输出子系统 tape 的指标：
//! - `node_tape_io_now`（Gauge，in_flight）；
//! - `node_tape_io_time_seconds_total` / `_read_time_seconds_total` /
//!   `_write_time_seconds_total`（Counter，io_ns/read_ns/write_ns 乘 1e-9
//!   转秒）；
//! - `node_tape_io_others_total`（other_cnt）、`node_tape_read_bytes_total`
//!   （read_byte_cnt）、`node_tape_reads_completed_total`（read_cnt）、
//!   `node_tape_residual_total`（resid_cnt）、`node_tape_written_bytes_total`
//!   （write_byte_cnt）、`node_tape_writes_completed_total`（write_cnt）。
//!
//! 计数文件缺失按 0 计（对齐 Go 零值），stats 目录缺失或计数值非法按错误
//! 处理（对齐 Go）。
//!
//! 偏离点：
//! - 未移植 `--collector.tapestats.ignored-devices` 正则过滤 CLI 参数；
//! - scsi_tape 目录缺失时返回空指标族（Go 侧为 ErrNoData）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// SCSI 磁带设备目录（相对 sys_path）
const TAPE_DIR: &str = "class/scsi_tape";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;

pub struct TapestatsCollector {
    sys_path: PathBuf,
}

impl TapestatsCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for TapestatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 磁带统计计数（对应 procfs sysfs TapeStats，缺省字段为 0）
#[derive(Debug, Default)]
struct TapeCounters {
    in_flight: u64,
    io_ns: u64,
    other_cnt: u64,
    read_byte_cnt: u64,
    read_cnt: u64,
    read_ns: u64,
    resid_cnt: u64,
    write_byte_cnt: u64,
    write_cnt: u64,
    write_ns: u64,
}

/// 从目录名提取编号（st0 → "0"）；无编号返回 None
/// （同 edac.rs 的判定：前缀 + 纯数字，等价于 procfs 的 ^st\d+$ 正则）
fn dir_number(name: &str, prefix: &str) -> Option<String> {
    let rest = name.strip_prefix(prefix)?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(rest.to_string())
}

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: TAPE_DIR,
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

/// 读取单个磁带设备的 stats/ 计数（未知文件忽略；目录缺失/计数值非法
/// 按错误处理，对齐 Go parseSCSITape）
fn read_tape_counters(tape_path: &Path) -> Result<TapeCounters, CollectorError> {
    let mut counters = TapeCounters::default();
    for entry in std::fs::read_dir(tape_path.join("stats"))? {
        let entry = entry?;
        // 对齐 Go：仅常规文件参与（符号链接/目录跳过）
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        // 对齐 Go：先读文件（读取失败即报错），再按文件名匹配字段
        let value = sys_read_file(&path)?;
        let Some(field) = entry.file_name().into_string().ok() else {
            continue;
        };
        let parse = |value: &str| -> Result<u64, CollectorError> {
            parse_uint_base0(value).map_err(|error| CollectorError::Parse {
                file: TAPE_DIR,
                reason: format!("{} 值非法: {error}", path.display()),
            })
        };
        match field.as_str() {
            "in_flight" => counters.in_flight = parse(&value)?,
            "io_ns" => counters.io_ns = parse(&value)?,
            "other_cnt" => counters.other_cnt = parse(&value)?,
            "read_byte_cnt" => counters.read_byte_cnt = parse(&value)?,
            "read_cnt" => counters.read_cnt = parse(&value)?,
            "read_ns" => counters.read_ns = parse(&value)?,
            "resid_cnt" => counters.resid_cnt = parse(&value)?,
            "write_byte_cnt" => counters.write_byte_cnt = parse(&value)?,
            "write_cnt" => counters.write_cnt = parse(&value)?,
            "write_ns" => counters.write_ns = parse(&value)?,
            _ => {}
        }
    }
    Ok(counters)
}

impl Collector for TapestatsCollector {
    fn name(&self) -> &'static str {
        "tapestats"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let tape_dir = self.sys_path.join(TAPE_DIR);
        let mut tape_paths: Vec<PathBuf> = match std::fs::read_dir(&tape_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| dir_number(name, "st"))
                        .is_some()
                })
                .collect(),
            // scsi_tape 目录缺失（无磁带设备）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        // 对齐 Go ReadDir 的设备名字典序
        tape_paths.sort();

        let mut io_now = MetricFamily::new(
            "node_tape_io_now",
            "The number of I/Os currently outstanding to this device.",
            MetricType::Gauge,
        );
        let mut io_time_seconds = MetricFamily::new(
            "node_tape_io_time_seconds_total",
            "The amount of time spent waiting for all I/O to complete (including read and write). This includes tape movement commands such as seeking between file or set marks and implicit tape movement such as when rewind on close tape devices are used.",
            MetricType::Counter,
        );
        let mut io_others = MetricFamily::new(
            "node_tape_io_others_total",
            "The number of I/Os issued to the tape drive other than read or write commands. The time taken to complete these commands uses the following calculation io_time_seconds_total-read_time_seconds_total-write_time_seconds_total",
            MetricType::Counter,
        );
        let mut read_bytes = MetricFamily::new(
            "node_tape_read_bytes_total",
            "The number of bytes read from the tape drive.",
            MetricType::Counter,
        );
        let mut reads_completed = MetricFamily::new(
            "node_tape_reads_completed_total",
            "The number of read requests issued to the tape drive.",
            MetricType::Counter,
        );
        let mut read_time_seconds = MetricFamily::new(
            "node_tape_read_time_seconds_total",
            "The amount of time spent waiting for read requests to complete.",
            MetricType::Counter,
        );
        let mut residual = MetricFamily::new(
            "node_tape_residual_total",
            "The number of times during a read or write we found the residual amount to be non-zero. This should mean that a program is issuing a read larger thean the block size on tape. For write not all data made it to tape.",
            MetricType::Counter,
        );
        let mut written_bytes = MetricFamily::new(
            "node_tape_written_bytes_total",
            "The number of bytes written to the tape drive.",
            MetricType::Counter,
        );
        let mut writes_completed = MetricFamily::new(
            "node_tape_writes_completed_total",
            "The number of write requests issued to the tape drive.",
            MetricType::Counter,
        );
        let mut write_time_seconds = MetricFamily::new(
            "node_tape_write_time_seconds_total",
            "The amount of time spent waiting for write requests to complete.",
            MetricType::Counter,
        );

        for tape_path in tape_paths {
            let Some(device) = tape_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let counters = read_tape_counters(&tape_path)?;
            let device_label = ("device".to_string(), device.to_string());
            io_now.push_labeled(vec![device_label.clone()], counters.in_flight as f64);
            // 纳秒转秒（与 Go 同运算：计数 × 1e-9）
            io_time_seconds.push_labeled(
                vec![device_label.clone()],
                counters.io_ns as f64 * 0.000000001,
            );
            io_others.push_labeled(vec![device_label.clone()], counters.other_cnt as f64);
            read_bytes.push_labeled(vec![device_label.clone()], counters.read_byte_cnt as f64);
            reads_completed.push_labeled(vec![device_label.clone()], counters.read_cnt as f64);
            read_time_seconds.push_labeled(
                vec![device_label.clone()],
                counters.read_ns as f64 * 0.000000001,
            );
            residual.push_labeled(vec![device_label.clone()], counters.resid_cnt as f64);
            written_bytes.push_labeled(vec![device_label.clone()], counters.write_byte_cnt as f64);
            writes_completed.push_labeled(vec![device_label.clone()], counters.write_cnt as f64);
            write_time_seconds
                .push_labeled(vec![device_label], counters.write_ns as f64 * 0.000000001);
        }

        Ok(vec![
            io_now,
            io_time_seconds,
            io_others,
            read_bytes,
            reads_completed,
            read_time_seconds,
            residual,
            written_bytes,
            writes_completed,
            write_time_seconds,
        ])
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
        let collector = TapestatsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 10);
        assert_eq!(families[0].name, "node_tape_io_now");
        assert_eq!(families[9].name, "node_tape_write_time_seconds_total");
        // 仅 ^st\d+$ 命中（nst0/st0a/st0l/st0m 排除）
        assert_eq!(families[0].samples.len(), 1);
        assert_eq!(value_of(&families[0], &[("device", "st0")]), 1.0);
        // 纳秒转秒（与 Go 同运算保证位级一致）
        assert_eq!(
            value_of(&families[1], &[("device", "st0")]),
            9247011087720.0_f64 * 0.000000001
        );
        assert_eq!(value_of(&families[2], &[("device", "st0")]), 1409.0);
        assert_eq!(value_of(&families[3], &[("device", "st0")]), 979383912.0);
        assert_eq!(value_of(&families[4], &[("device", "st0")]), 3741.0);
        assert_eq!(
            value_of(&families[5], &[("device", "st0")]),
            33788355744.0_f64 * 0.000000001
        );
        assert_eq!(value_of(&families[6], &[("device", "st0")]), 19.0);
        assert_eq!(
            value_of(&families[7], &[("device", "st0")]),
            1496246784000.0
        );
        assert_eq!(value_of(&families[8], &[("device", "st0")]), 53772916.0);
        assert_eq!(
            value_of(&families[9], &[("device", "st0")]),
            5233597394395.0_f64 * 0.000000001
        );
    }

    #[test]
    fn test_missing_tape_dir_yields_empty() {
        let collector = TapestatsCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
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
            parse_uint_base0("0x2").unwrap_or_else(|e| panic!("解析失败: {e}")),
            2
        );
        assert_eq!(
            parse_uint_base0("0X10").unwrap_or_else(|e| panic!("解析失败: {e}")),
            16
        );
        assert_eq!(
            parse_uint_base0("010").unwrap_or_else(|e| panic!("解析失败: {e}")),
            8
        );
        assert!(parse_uint_base0("08").is_err());
        assert!(parse_uint_base0("").is_err());
        assert!(parse_uint_base0("1EOF").is_err());
    }
}
