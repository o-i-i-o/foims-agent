//! logical_disk 采集器（对齐 Go `internal/collector/logical_disk/`）。
//!
//! PDH 对象 `LogicalDisk`，通配实例；输出 18 个指标族，标签 {volume} =
//! 实例名。readonly / info 两族来自卷信息 API，其余 16 族来自 PDH，
//! 发射顺序镜像 Go Collect()。
//!
//! 换算语义：`% Disk Read/Write Time`、`% Idle Time` 为 PERF_100NSEC_TIMER，
//! raw 值经 [`super::raw_to_value`] 自动 ×1e-7；两个 `Avg. Disk * Queue
//! Length`（PERF_COUNTER_100NS_QUEUELEN_TYPE）与三个 `Avg. Disk sec/*`
//! （PERF_AVERAGE_TIMER）走 setRawValue 的 default 分支 raw 原值输出，
//! 由本采集器显式 ×1e-7（对齐 Go 代码里的 `*pdh.TicksToSecondScaleFactor`）。
//!
//! ## 与 Go 的已知偏离
//! - `bitlocker_status` 子采集器跳过（默认未启用，需 fveapi.dll）；
//! - IOCTL 卷磁盘扩展区未移植，info 指标的 disk 标签恒为空串；
//! - 挂载点枚举（FindFirstVolume/GetVolumePathNamesForVolumeName）未移植，
//!   根路径统一取 实例名 + `\`，HarddiskVolume 与卷 GUID 路径特例未处理；
//! - 容量统一经 GetDiskFreeSpaceExW（Go 优先 GetDiskSpaceInformationW，
//!   Server 2016 缺该 API 时才回退 GetDiskFreeSpaceEx，后者在有配额时
//!   总容量为调用方配额口径）；
//! - 卷信息的静态部分（磁盘号/驱动器类型）无跨采集缓存（Go 缓存 10 分钟）；
//! - volume-include/exclude 正则过滤未移植。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::{CollectorRow, TICKS_TO_SECONDS};

/// 1 MiB（容量回退值的换算：Go 的 `*1024*1024`）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const MIB: f64 = 1024.0 * 1024.0;

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 顺序即索引约定，勿调整）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "Avg. Disk Read Queue Length",
    "Avg. Disk sec/Read",
    "Avg. Disk sec/Transfer",
    "Avg. Disk sec/Write",
    "Avg. Disk Write Queue Length",
    "Current Disk Queue Length",
    "Free Megabytes",
    "Disk Read Bytes/sec",
    "Disk Reads/sec",
    "Disk Write Bytes/sec",
    "Disk Writes/sec",
    "% Disk Read Time",
    "% Disk Write Time",
    "% Free Space,secondvalue",
    "% Idle Time",
    "Split IO/Sec",
];

// 上述清单的索引常量（采集器取值用；跨平台供发射函数与测试引用）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const AVG_READ_QUEUE: usize = 0;
    pub(super) const READ_LATENCY: usize = 1;
    pub(super) const READ_WRITE_LATENCY: usize = 2;
    pub(super) const WRITE_LATENCY: usize = 3;
    pub(super) const AVG_WRITE_QUEUE: usize = 4;
    pub(super) const REQUESTS_QUEUED: usize = 5;
    pub(super) const FREE_MEGABYTES: usize = 6;
    pub(super) const READ_BYTES: usize = 7;
    pub(super) const READS: usize = 8;
    pub(super) const WRITE_BYTES: usize = 9;
    pub(super) const WRITES: usize = 10;
    pub(super) const READ_TIME: usize = 11;
    pub(super) const WRITE_TIME: usize = 12;
    pub(super) const PERCENT_FREE_SPACE: usize = 13;
    pub(super) const IDLE_TIME: usize = 14;
    pub(super) const SPLIT_IOS: usize = 15;
}

/// 单卷信息快照（跨平台纯数据，windows 分支从卷信息 API 映射；
/// 信息读取失败时用 Default 的空快照，仅 volume_type 另行填充）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeSnapshot {
    /// 驱动器类型文本（GetDriveTypeW，见 [`drive_type_name`]）
    pub volume_type: String,
    /// 卷标
    pub label: String,
    /// 文件系统名（NTFS/FAT32…）
    pub filesystem: String,
    /// 卷序列号（大写十六进制）
    pub serial_number: String,
    /// 卷信息是否读取成功（Go 的 hasReadonly）
    pub has_readonly: bool,
    /// 卷是否只读（1.0/0.0，仅 has_readonly 为真时输出）
    pub readonly: f64,
    /// 空闲字节（None 时回退 PDH 计数器，Go 的 hasFreeBytes）
    pub free_bytes: Option<u64>,
    /// 总字节（None 时回退 PDH 计数器，Go 的 hasSizeBytes）
    pub size_bytes: Option<u64>,
}

/// GetDriveTypeW 返回码 → 文本（对齐 Go getDriveType，windows.h DRIVE_* 常量）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn drive_type_name(code: u32) -> &'static str {
    match code {
        1 => "norootdir",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        // DRIVE_UNKNOWN(0) 与其余未知值同按 unknown 处理（对齐 Go default）
        _ => "unknown",
    }
}

/// PDH 值在 raw 换算之外的采集器级处理方式
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
enum Scaling {
    /// 原值直接输出
    Plain,
    /// 100ns tick → 秒（×[`super::TICKS_TO_SECONDS`]，Go 的显式换算）
    Ticks,
    /// 空闲容量回退：Free Megabytes × 1 MiB
    FreeFallback,
    /// 总容量回退：% Free Space 的 SecondValue × 1 MiB
    SizeFallback,
}

/// logical_disk 采集器：持有 PDH 计数器集
pub struct LogicalDiskCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
}

impl LogicalDiskCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("LogicalDisk", COUNTERS) {
                Ok(set) => Self { set: Some(set) },
                // PDH 初始化失败时保留空集，collect 时按 NoData 上报，
                // 保证单采集器故障不拖垮其余采集器
                Err(error) => {
                    tracing::warn!(%error, "logical_disk 采集器 PDH 初始化失败");
                    Self { set: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for LogicalDiskCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for LogicalDiskCollector {
    fn name(&self) -> &'static str {
        "logical_disk"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        match &self.set {
            None => Err(CollectorError::NoData),
            Some(set) => {
                set.collect().map_err(super::collector_error)?;
                let rows = set.sample_instanced().map_err(super::collector_error)?;
                Ok(emit_logical_disk(&rows, &read_volume_snapshot))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// 读取单个卷的信息快照（windows 专用）：根路径取 实例名 + `\`，
/// 卷信息读取失败按空快照处理但驱动器类型仍取 GetDriveTypeW
/// （对齐 Go：info 结构零值 + volumeType 独立读取）。
#[cfg(target_os = "windows")]
fn read_volume_snapshot(instance: &str) -> VolumeSnapshot {
    use crate::ffi;

    let root = format!("{instance}\\");
    let volume_type = drive_type_name(ffi::drive_type(&root)).to_string();
    let Ok(info) = ffi::volume_information(&root) else {
        return VolumeSnapshot {
            volume_type,
            ..Default::default()
        };
    };
    let space = ffi::volume_space(&root).ok();
    VolumeSnapshot {
        volume_type,
        label: info.label,
        filesystem: info.filesystem,
        serial_number: info.serial_number,
        has_readonly: true,
        readonly: if info.readonly { 1.0 } else { 0.0 },
        free_bytes: space.as_ref().map(|space| space.free_bytes),
        size_bytes: space.map(|space| space.total_bytes),
    }
}

/// {volume} 标签（实例名）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn volume_labels(instance: &str) -> Vec<(String, String)> {
    vec![("volume".to_string(), instance.to_string())]
}

/// 由通配实例样本构造全部 logical_disk 指标族（纯函数，Linux 宿主可测）。
///
/// `volume_of` 提供每个实例的卷信息快照。族序镜像 Go Collect()：
/// readonly → info → requests_queued → avg_read/avg_write → read/write
/// bytes → reads/writes → read/write_seconds → free/size → idle →
/// split_ios → 三个 latency。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_logical_disk(
    rows: &[CollectorRow],
    volume_of: &dyn Fn(&str) -> VolumeSnapshot,
) -> Vec<MetricFamily> {
    use idx::{
        AVG_READ_QUEUE, AVG_WRITE_QUEUE, FREE_MEGABYTES, IDLE_TIME, PERCENT_FREE_SPACE, READ_BYTES,
        READ_LATENCY, READ_TIME, READ_WRITE_LATENCY, READS, REQUESTS_QUEUED, SPLIT_IOS,
        WRITE_BYTES, WRITE_LATENCY, WRITE_TIME, WRITES,
    };

    // 每实例的卷信息快照只取一次，readonly/info 与容量回退共用
    let snapshots: Vec<(&CollectorRow, VolumeSnapshot)> = rows
        .iter()
        .map(|row| (row, volume_of(&row.instance)))
        .collect();
    let mut out = Vec::with_capacity(18);

    // readonly：仅卷信息读取成功时输出（Go 的 hasReadonly）
    let mut readonly = MetricFamily::new(
        "windows_logical_disk_readonly",
        "Whether the logical disk is read-only",
        MetricType::Gauge,
    );
    for (row, info) in &snapshots {
        if info.has_readonly {
            readonly.push_labeled(volume_labels(&row.instance), info.readonly);
        }
    }
    if !readonly.samples.is_empty() {
        out.push(readonly);
    }

    // info：标签序 disk/type/volume/volume_name/filesystem/serial_number
    // （disk 即 Go 的 diskIDs，本移植无 IOCTL 数据恒为空串）
    let mut info = MetricFamily::new(
        "windows_logical_disk_info",
        "A metric with a constant '1' value labeled with logical disk information",
        MetricType::Gauge,
    );
    for (row, volume) in &snapshots {
        info.push_labeled(
            vec![
                ("disk".to_string(), String::new()),
                ("type".to_string(), volume.volume_type.clone()),
                ("volume".to_string(), row.instance.clone()),
                ("volume_name".to_string(), volume.label.clone()),
                ("filesystem".to_string(), volume.filesystem.clone()),
                ("serial_number".to_string(), volume.serial_number.clone()),
            ],
            1.0,
        );
    }
    if !info.samples.is_empty() {
        out.push(info);
    }

    // PDH 系指标（顺序即发射顺序）
    let definitions: &[(&str, &str, MetricType, usize, Scaling)] = &[
        (
            "windows_logical_disk_requests_queued",
            "The number of requests queued to the disk (LogicalDisk.CurrentDiskQueueLength)",
            MetricType::Gauge,
            REQUESTS_QUEUED,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_avg_read_requests_queued",
            "DEPRECATED: use rate(windows_logical_disk_read_seconds_total). \
             Cumulative read queue length in seconds, identical to windows_logical_disk_read_seconds_total (LogicalDisk.AvgDiskReadQueueLength)",
            MetricType::Gauge,
            AVG_READ_QUEUE,
            Scaling::Ticks,
        ),
        (
            "windows_logical_disk_avg_write_requests_queued",
            "DEPRECATED: use rate(windows_logical_disk_write_seconds_total). \
             Cumulative write queue length in seconds, identical to windows_logical_disk_write_seconds_total (LogicalDisk.AvgDiskWriteQueueLength)",
            MetricType::Gauge,
            AVG_WRITE_QUEUE,
            Scaling::Ticks,
        ),
        (
            "windows_logical_disk_read_bytes_total",
            "The number of bytes transferred from the disk during read operations (LogicalDisk.DiskReadBytesPerSec)",
            MetricType::Counter,
            READ_BYTES,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_reads_total",
            "The number of read operations on the disk (LogicalDisk.DiskReadsPerSec)",
            MetricType::Counter,
            READS,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_write_bytes_total",
            "The number of bytes transferred to the disk during write operations (LogicalDisk.DiskWriteBytesPerSec)",
            MetricType::Counter,
            WRITE_BYTES,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_writes_total",
            "The number of write operations on the disk (LogicalDisk.DiskWritesPerSec)",
            MetricType::Counter,
            WRITES,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_read_seconds_total",
            "Seconds that the disk was busy servicing read requests (LogicalDisk.PercentDiskReadTime)",
            MetricType::Counter,
            READ_TIME,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_write_seconds_total",
            "Seconds that the disk was busy servicing write requests (LogicalDisk.PercentDiskWriteTime)",
            MetricType::Counter,
            WRITE_TIME,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_free_bytes",
            "Free space in bytes",
            MetricType::Gauge,
            FREE_MEGABYTES,
            Scaling::FreeFallback,
        ),
        (
            "windows_logical_disk_size_bytes",
            "Total space in bytes",
            MetricType::Gauge,
            PERCENT_FREE_SPACE,
            Scaling::SizeFallback,
        ),
        (
            "windows_logical_disk_idle_seconds_total",
            "Seconds that the disk was idle (LogicalDisk.PercentIdleTime)",
            MetricType::Counter,
            IDLE_TIME,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_split_ios_total",
            "The number of I/Os to the disk were split into multiple I/Os (LogicalDisk.SplitIOPerSec)",
            MetricType::Counter,
            SPLIT_IOS,
            Scaling::Plain,
        ),
        (
            "windows_logical_disk_read_latency_seconds_total",
            "Shows the average time, in seconds, of a read operation from the disk (LogicalDisk.AvgDiskSecPerRead)",
            MetricType::Counter,
            READ_LATENCY,
            Scaling::Ticks,
        ),
        (
            "windows_logical_disk_write_latency_seconds_total",
            "Shows the average time, in seconds, of a write operation to the disk (LogicalDisk.AvgDiskSecPerWrite)",
            MetricType::Counter,
            WRITE_LATENCY,
            Scaling::Ticks,
        ),
        (
            "windows_logical_disk_read_write_latency_seconds_total",
            "Shows the time, in seconds, of the average disk transfer (LogicalDisk.AvgDiskSecPerTransfer)",
            MetricType::Counter,
            READ_WRITE_LATENCY,
            Scaling::Ticks,
        ),
    ];

    for (name, help, mtype, index, scaling) in definitions {
        let mut family = MetricFamily::new(name, help, *mtype);
        for (row, volume) in &snapshots {
            // sample_instanced 已保证全计数器有效，缺项仅可能来自直接调用发射函数的测试
            let Some(sample) = row.values.get(*index).and_then(Option::as_ref) else {
                continue;
            };
            let value = match scaling {
                Scaling::Plain => sample.value(),
                Scaling::Ticks => sample.value() * TICKS_TO_SECONDS,
                // Free Megabytes 被 Windows 缓存且仅整 MB 更新，是卷容量
                // 直读失败时的回退（对齐 Go 的回退顺序）
                Scaling::FreeFallback => {
                    volume.free_bytes.map_or(sample.value() * MIB, |v| v as f64)
                }
                Scaling::SizeFallback => volume
                    .size_bytes
                    .map_or(sample.second_value() * MIB, |v| v as f64),
            };
            family.push_labeled(volume_labels(&row.instance), value);
        }
        if !family.samples.is_empty() {
            out.push(family);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::RawSample;
    use super::*;

    /// 以原值类型构造样本行（counter_type=0 走 default 分支原值输出）
    fn row(instance: &str, first: i64, second: i64) -> CollectorRow {
        CollectorRow {
            instance: instance.to_string(),
            values: COUNTERS
                .iter()
                .map(|_| {
                    Some(RawSample {
                        first,
                        second,
                        counter_type: 0,
                    })
                })
                .collect(),
        }
    }

    /// 默认卷信息快照（含 readonly 与容量）
    fn snapshot(free: Option<u64>, size: Option<u64>) -> VolumeSnapshot {
        VolumeSnapshot {
            volume_type: "fixed".to_string(),
            label: "System".to_string(),
            filesystem: "NTFS".to_string(),
            serial_number: "ABCD1234".to_string(),
            has_readonly: true,
            readonly: 0.0,
            free_bytes: free,
            size_bytes: size,
        }
    }

    /// 18 个指标族齐全，顺序与标签与 Go 发射顺序一致
    #[test]
    fn test_emit_logical_disk_family_layout() {
        let rows = vec![row("C:", 1_000, 500), row("D:", 2_000, 700)];
        let families = emit_logical_disk(&rows, &|_| snapshot(Some(123), Some(456)));

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names.len(), 18, "{names:?}");
        assert_eq!(names[0], "windows_logical_disk_readonly");
        assert_eq!(names[1], "windows_logical_disk_info");
        assert_eq!(names[2], "windows_logical_disk_requests_queued");
        assert_eq!(names[3], "windows_logical_disk_avg_read_requests_queued");
        assert_eq!(names[4], "windows_logical_disk_avg_write_requests_queued");
        assert_eq!(names[10], "windows_logical_disk_write_seconds_total");
        assert_eq!(names[11], "windows_logical_disk_free_bytes");
        assert_eq!(names[12], "windows_logical_disk_size_bytes");
        assert_eq!(
            names[17],
            "windows_logical_disk_read_write_latency_seconds_total"
        );

        // info 标签序 disk/type/volume/volume_name/filesystem/serial_number
        let info = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_info")
            .unwrap_or_else(|| panic!("缺少 info"));
        assert_eq!(
            info.samples[0].labels,
            vec![
                ("disk".to_string(), String::new()),
                ("type".to_string(), "fixed".to_string()),
                ("volume".to_string(), "C:".to_string()),
                ("volume_name".to_string(), "System".to_string()),
                ("filesystem".to_string(), "NTFS".to_string()),
                ("serial_number".to_string(), "ABCD1234".to_string()),
            ]
        );
        assert_eq!(info.samples[1].labels[2].1, "D:");

        // {volume} 标签与 PDH 原值
        let requests = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_requests_queued")
            .unwrap_or_else(|| panic!("缺少 requests_queued"));
        assert_eq!(requests.mtype, MetricType::Gauge);
        assert_eq!(requests.samples[1].value, 2_000.0);
    }

    /// avg queue 与三个 latency 显式 ×1e-7（raw 原值输入）
    #[test]
    fn test_ticks_scaling() {
        let rows = vec![row("C:", 10_000_000, 0)];
        let families = emit_logical_disk(&rows, &|_| snapshot(Some(1), Some(1)));
        for name in [
            "windows_logical_disk_avg_read_requests_queued",
            "windows_logical_disk_avg_write_requests_queued",
            "windows_logical_disk_read_latency_seconds_total",
            "windows_logical_disk_write_latency_seconds_total",
            "windows_logical_disk_read_write_latency_seconds_total",
        ] {
            let family = families
                .iter()
                .find(|family| family.name == name)
                .unwrap_or_else(|| panic!("缺少 {name}"));
            assert_eq!(family.samples[0].value, 1.0, "{name}");
        }
    }

    /// 容量回退：快照缺容量时用 PDH 计数器（Free Megabytes × 1 MiB、
    /// % Free Space 的 SecondValue × 1 MiB）；有值时覆盖
    #[test]
    fn test_free_size_fallback() {
        let rows = vec![row("C:", 2_000, 3_000)];

        let families = emit_logical_disk(&rows, &|_| snapshot(None, None));
        let free = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_free_bytes")
            .unwrap_or_else(|| panic!("缺少 free_bytes"));
        assert_eq!(free.samples[0].value, 2_000.0 * 1_048_576.0);
        let size = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_size_bytes")
            .unwrap_or_else(|| panic!("缺少 size_bytes"));
        assert_eq!(size.samples[0].value, 3_000.0 * 1_048_576.0);

        let families = emit_logical_disk(&rows, &|_| snapshot(Some(7), Some(9)));
        let free = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_free_bytes")
            .unwrap_or_else(|| panic!("缺少 free_bytes"));
        assert_eq!(free.samples[0].value, 7.0);
        let size = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_size_bytes")
            .unwrap_or_else(|| panic!("缺少 size_bytes"));
        assert_eq!(size.samples[0].value, 9.0);
    }

    /// readonly 仅在卷信息可读时输出，值取快照标志
    #[test]
    fn test_readonly_only_when_known() {
        let rows = vec![row("C:", 1, 1)];

        let no_readonly = VolumeSnapshot {
            has_readonly: false,
            ..snapshot(None, None)
        };
        let families = emit_logical_disk(&rows, &|_| no_readonly.clone());
        assert_eq!(families.len(), 17, "缺 readonly 时其余 17 族仍齐全");
        assert!(
            families
                .iter()
                .all(|family| family.name != "windows_logical_disk_readonly")
        );

        let readonly_yes = VolumeSnapshot {
            readonly: 1.0,
            ..snapshot(None, None)
        };
        let families = emit_logical_disk(&rows, &|_| readonly_yes.clone());
        let family = families
            .iter()
            .find(|family| family.name == "windows_logical_disk_readonly")
            .unwrap_or_else(|| panic!("缺少 readonly"));
        assert_eq!(family.samples[0].value, 1.0);
        assert_eq!(
            family.samples[0].labels,
            vec![("volume".to_string(), "C:".to_string())]
        );
    }

    /// 驱动器类型映射（windows.h DRIVE_* 常量）
    #[test]
    fn test_drive_type_name() {
        assert_eq!(drive_type_name(0), "unknown");
        assert_eq!(drive_type_name(1), "norootdir");
        assert_eq!(drive_type_name(2), "removable");
        assert_eq!(drive_type_name(3), "fixed");
        assert_eq!(drive_type_name(4), "remote");
        assert_eq!(drive_type_name(5), "cdrom");
        assert_eq!(drive_type_name(6), "ramdisk");
        assert_eq!(drive_type_name(42), "unknown");
    }

    /// 计数器清单与索引常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS.len(), 16);
        assert_eq!(COUNTERS[idx::AVG_READ_QUEUE], "Avg. Disk Read Queue Length");
        assert_eq!(
            COUNTERS[idx::AVG_WRITE_QUEUE],
            "Avg. Disk Write Queue Length"
        );
        assert_eq!(COUNTERS[idx::REQUESTS_QUEUED], "Current Disk Queue Length");
        assert_eq!(COUNTERS[idx::FREE_MEGABYTES], "Free Megabytes");
        assert_eq!(
            COUNTERS[idx::PERCENT_FREE_SPACE],
            "% Free Space,secondvalue"
        );
        assert_eq!(COUNTERS[idx::READ_LATENCY], "Avg. Disk sec/Read");
        assert_eq!(COUNTERS[idx::SPLIT_IOS], "Split IO/Sec");
    }
}
