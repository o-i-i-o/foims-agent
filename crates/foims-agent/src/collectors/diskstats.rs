//! diskstats 采集器：块设备 I/O 统计。
//!
//! 对齐 node_exporter `diskstats_linux.go` + `diskstats_common.go`：
//! 解析 /proc/diskstats，逐字移植 17 个 `node_disk_*` 指标族（device 标签、
//! counter/gauge 类型与 help 文案），扇区按 512 字节换算、毫秒 tick 按千分之一
//! 换算为秒。默认设备过滤对齐 `diskstatsDefaultIgnoredDevices`
//! （`^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`，crate 未引入 regex
//! 依赖，以等价的手写匹配实现）。
//!
//! 未移植：`node_disk_info`、`node_disk_filesystem_info`、
//! `node_disk_device_mapper_info`、`node_disk_ata_*` 等 udev/sysfs 可选扩展
//! （依赖 /run/udev/data 与 /sys/block 注入支持）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const DISKSTATS_FILE: &str = "diskstats";

/// 毫秒 tick → 秒（内核以 1000 Hz 记录 I/O tick）
const SECONDS_PER_TICK: f64 = 1.0 / 1000.0;
/// 读/写扇区数是"标准 UNIX 512 字节扇区"，与设备实际块大小无关
const UNIX_SECTOR_SIZE: f64 = 512.0;

/// 统计字段描述表（名称后缀、help、类型），顺序与 Go 源 descs 切片一致，
/// 对应 /proc/diskstats 每行第 4 列起的统计字段
const DISK_STATS_DESCS: [(&str, &str, MetricType); 17] = [
    (
        "reads_completed_total",
        "The total number of reads completed successfully.",
        MetricType::Counter,
    ),
    (
        "reads_merged_total",
        "The total number of reads merged.",
        MetricType::Counter,
    ),
    (
        "read_bytes_total",
        "The total number of bytes read successfully.",
        MetricType::Counter,
    ),
    (
        "read_time_seconds_total",
        "The total number of seconds spent by all reads.",
        MetricType::Counter,
    ),
    (
        "writes_completed_total",
        "The total number of writes completed successfully.",
        MetricType::Counter,
    ),
    (
        "writes_merged_total",
        "The number of writes merged.",
        MetricType::Counter,
    ),
    (
        "written_bytes_total",
        "The total number of bytes written successfully.",
        MetricType::Counter,
    ),
    (
        "write_time_seconds_total",
        "This is the total number of seconds spent by all writes.",
        MetricType::Counter,
    ),
    (
        "io_now",
        "The number of I/Os currently in progress.",
        MetricType::Gauge,
    ),
    (
        "io_time_seconds_total",
        "Total seconds spent doing I/Os.",
        MetricType::Counter,
    ),
    (
        "io_time_weighted_seconds_total",
        "The weighted # of seconds spent doing I/Os.",
        MetricType::Counter,
    ),
    (
        "discards_completed_total",
        "The total number of discards completed successfully.",
        MetricType::Counter,
    ),
    (
        "discards_merged_total",
        "The total number of discards merged.",
        MetricType::Counter,
    ),
    (
        "discarded_sectors_total",
        "The total number of sectors discarded successfully.",
        MetricType::Counter,
    ),
    (
        "discard_time_seconds_total",
        "This is the total number of seconds spent by all discards.",
        MetricType::Counter,
    ),
    (
        "flush_requests_total",
        // 逐字对齐 Go 源：此句结尾无句号
        "The total number of flush requests completed successfully",
        MetricType::Counter,
    ),
    (
        "flush_requests_time_seconds_total",
        "This is the total number of seconds spent by all flush requests.",
        MetricType::Counter,
    ),
];

pub struct DiskstatsCollector {
    proc_path: PathBuf,
}

impl DiskstatsCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for DiskstatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 字符串是否为非空 ASCII 数字串（模拟正则 \d+）
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// 默认设备过滤，等价于正则
/// `^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`
/// （对齐 diskstatsDefaultIgnoredDevices）
fn is_ignored_device(device: &str) -> bool {
    // z?ram\d+
    for prefix in ["zram", "ram"] {
        if let Some(rest) = device.strip_prefix(prefix)
            && is_digits(rest)
        {
            return true;
        }
    }
    // loop\d+ / fd\d+
    for prefix in ["loop", "fd"] {
        if let Some(rest) = device.strip_prefix(prefix)
            && is_digits(rest)
        {
            return true;
        }
    }
    // (h|s|v|xv)d[a-z]\d+
    for prefix in ["hd", "sd", "vd", "xvd"] {
        if let Some(rest) = device.strip_prefix(prefix) {
            let mut chars = rest.chars();
            let first = chars.next();
            if first.is_some_and(|c| c.is_ascii_lowercase()) && is_digits(chars.as_str()) {
                return true;
            }
        }
    }
    // nvme\d+n\d+p\d+
    if let Some(rest) = device.strip_prefix("nvme")
        && let Some(major_end) = rest.find('n')
        && is_digits(&rest[..major_end])
    {
        let minor_part = &rest[major_end + 1..];
        if let Some(partition_start) = minor_part.find('p')
            && is_digits(&minor_part[..partition_start])
            && is_digits(&minor_part[partition_start + 1..])
        {
            return true;
        }
    }
    false
}

/// 解析 /proc/diskstats：返回 (设备名, 原始统计值列表)。
/// 统计值列表长度即 Go procfs 的 IoStatsCount - 3（总字段数减 major/minor/device），
/// 新内核的 discard/flush 字段在旧内核行中缺失。
fn parse_diskstats(text: &str) -> Result<Vec<(String, Vec<f64>)>, CollectorError> {
    let mut devices = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 每行至少 major minor device + 1 个统计字段
        if fields.len() < 4 {
            return Err(CollectorError::Parse {
                file: DISKSTATS_FILE,
                reason: format!("字段数不足: {line}"),
            });
        }
        let device = fields[2];
        let mut values = Vec::with_capacity(fields.len() - 3);
        for field in &fields[3..] {
            let value: f64 = field.parse().map_err(|error| CollectorError::Parse {
                file: DISKSTATS_FILE,
                reason: format!("设备 {device} 统计值非法: {error}"),
            })?;
            values.push(value);
        }
        devices.push((device.to_string(), values));
    }
    Ok(devices)
}

impl Collector for DiskstatsCollector {
    fn name(&self) -> &'static str {
        "diskstats"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(DISKSTATS_FILE))?;
        let devices = parse_diskstats(&text)?;
        if devices.is_empty() {
            return Err(CollectorError::NoData);
        }

        // 每个指标族一个条目，样本按设备追加（对齐 Go registry 按指标名聚合输出）
        let mut families: Vec<MetricFamily> = DISK_STATS_DESCS
            .iter()
            .map(|(suffix, help, mtype)| {
                MetricFamily::new(&format!("node_disk_{suffix}"), help, *mtype)
            })
            .collect();

        for (device, values) in &devices {
            if is_ignored_device(device) {
                continue;
            }
            // 统计字段数超过描述表时截断（对齐 Go 循环固定 17 项 + i >= statCount break）
            for (index, raw) in values.iter().enumerate() {
                if index >= DISK_STATS_DESCS.len() {
                    break;
                }
                let value = match index {
                    // 读/写扇区数 → 字节数
                    2 | 6 => raw * UNIX_SECTOR_SIZE,
                    // 毫秒 tick → 秒
                    3 | 7 | 9 | 10 | 14 | 16 => raw * SECONDS_PER_TICK,
                    _ => *raw,
                };
                families[index].push_labeled(vec![("device".to_string(), device.clone())], value);
            }
        }
        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    /// 按设备标签取样本值
    fn device_value(family: &MetricFamily, device: &str) -> f64 {
        family
            .samples
            .iter()
            .find(|s| s.labels.iter().any(|(k, v)| k == "device" && v == device))
            .unwrap_or_else(|| panic!("缺少设备 {device} 样本"))
            .value
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = DiskstatsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));

        // 全部 17 个指标族名称与顺序对齐 Go 源 descs
        let expected = [
            "node_disk_reads_completed_total",
            "node_disk_reads_merged_total",
            "node_disk_read_bytes_total",
            "node_disk_read_time_seconds_total",
            "node_disk_writes_completed_total",
            "node_disk_writes_merged_total",
            "node_disk_written_bytes_total",
            "node_disk_write_time_seconds_total",
            "node_disk_io_now",
            "node_disk_io_time_seconds_total",
            "node_disk_io_time_weighted_seconds_total",
            "node_disk_discards_completed_total",
            "node_disk_discards_merged_total",
            "node_disk_discarded_sectors_total",
            "node_disk_discard_time_seconds_total",
            "node_disk_flush_requests_total",
            "node_disk_flush_requests_time_seconds_total",
        ];
        let names: Vec<&str> = families.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, expected.as_slice());

        // 扇区 → 字节换算（sda 读扇区 1003346126）
        let read_bytes = &families[2];
        assert_eq!(
            read_bytes.help,
            "The total number of bytes read successfully."
        );
        assert_eq!(
            device_value(read_bytes, "sda"),
            1003346126.0 * UNIX_SECTOR_SIZE
        );

        // tick → 秒换算（sda io tick 9653880；Go 期望值呈现为 9653.880000000001）
        assert_eq!(
            device_value(&families[9], "sda"),
            9653880.0 * SECONDS_PER_TICK
        );

        // 14 字段行（sdb）才有 discard 指标，17 字段行（sdc）才有 flush 指标
        assert_eq!(device_value(&families[11], "sdb"), 68851.0);
        assert_eq!(device_value(&families[15], "sdc"), 1555.0);
        assert_eq!(
            device_value(&families[16], "sdc"),
            1944.0 * SECONDS_PER_TICK
        );

        // 默认过滤后保留 15 台设备（与 node_exporter Go 测试的 io_now 一致）
        let io_now = &families[8];
        assert_eq!(io_now.mtype, MetricType::Gauge);
        assert_eq!(io_now.samples.len(), 15);

        // 被默认正则排除的设备不得出现
        let ignored = ["ram0", "loop0", "fd0", "sda1", "vda1", "nvme0n1p1", "sdb2"];
        for family in &families {
            for sample in &family.samples {
                for (key, value) in &sample.labels {
                    if key == "device" && ignored.contains(&value.as_str()) {
                        panic!("设备 {value} 未被过滤");
                    }
                }
            }
        }
    }

    #[test]
    fn test_is_ignored_device() {
        // 命中默认正则
        for device in [
            "ram0",
            "ram15",
            "zram0",
            "loop7",
            "fd0",
            "sda1",
            "sdb2",
            "vda12",
            "xvda3",
            "hdc1",
            "nvme0n1p2",
            "nvme12n3p45",
        ] {
            assert!(is_ignored_device(device), "{device} 应被过滤");
        }
        // 整盘设备与其它命名保留
        for device in [
            "sda",
            "vda",
            "xvdb",
            "nvme0n1",
            "dm-0",
            "mmcblk0",
            "mmcblk0p1",
            "sr0",
            "fd",
            "ram",
            "sdaa1",
            "nvmep0n1",
        ] {
            assert!(!is_ignored_device(device), "{device} 不应被过滤");
        }
    }

    #[test]
    fn test_parse_rejects_invalid_value() {
        assert!(matches!(
            parse_diskstats("8 0 sda abc"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            parse_diskstats("8 0"),
            Err(CollectorError::Parse { .. })
        ));
    }
}
