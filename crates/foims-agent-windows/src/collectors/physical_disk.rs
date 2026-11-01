//! physical_disk 采集器（对齐 Go `internal/collector/physical_disk/`）。
//!
//! PDH 对象 `PhysicalDisk`，通配实例；输出 12 个指标族（与
//! perfDataCounterValues 的 12 个 perfdata 标签一一对应，标签 {disk} =
//! 实例名首个空格前的截断，如 "1 C:" → "1"）。
//!
//! 换算语义：`% Disk Read/Write/Idle Time` 为 PERF_100NSEC_TIMER，raw 值经
//! [`super::raw_to_value`] 自动 ×1e-7；三个 `Avg. Disk sec/*`（延迟）为
//! PERF_AVERAGE_TIMER，raw 原值输出，由本采集器显式 ×1e-7（对齐 Go 的
//! `*pdh.TicksToSecondScaleFactor`）。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::{CollectorRow, TICKS_TO_SECONDS};

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 顺序即索引约定，勿调整）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "Current Disk Queue Length",
    "Disk Read Bytes/sec",
    "Disk Reads/sec",
    "Disk Write Bytes/sec",
    "Disk Writes/sec",
    "% Disk Read Time",
    "% Disk Write Time",
    "% Idle Time",
    "Split IO/Sec",
    "Avg. Disk sec/Read",
    "Avg. Disk sec/Write",
    "Avg. Disk sec/Transfer",
];

// 上述清单的索引常量（采集器取值用；跨平台供发射函数与测试引用）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const REQUESTS_QUEUED: usize = 0;
    pub(super) const READ_BYTES: usize = 1;
    pub(super) const READS: usize = 2;
    pub(super) const WRITE_BYTES: usize = 3;
    pub(super) const WRITES: usize = 4;
    pub(super) const READ_TIME: usize = 5;
    pub(super) const WRITE_TIME: usize = 6;
    pub(super) const IDLE_TIME: usize = 7;
    pub(super) const SPLIT_IOS: usize = 8;
    pub(super) const READ_LATENCY: usize = 9;
    pub(super) const WRITE_LATENCY: usize = 10;
    pub(super) const READ_WRITE_LATENCY: usize = 11;
}

/// physical_disk 采集器：持有 PDH 计数器集
pub struct PhysicalDiskCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
}

impl PhysicalDiskCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("PhysicalDisk", COUNTERS) {
                Ok(set) => Self { set: Some(set) },
                // PDH 初始化失败时保留空集，collect 时按 NoData 上报，
                // 保证单采集器故障不拖垮其余采集器
                Err(error) => {
                    tracing::warn!(%error, "physical_disk 采集器 PDH 初始化失败");
                    Self { set: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for PhysicalDiskCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for PhysicalDiskCollector {
    fn name(&self) -> &'static str {
        "physical_disk"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        match &self.set {
            None => Err(CollectorError::NoData),
            Some(set) => {
                set.collect().map_err(super::collector_error)?;
                let rows = set.sample_instanced().map_err(super::collector_error)?;
                Ok(emit_physical_disk(&rows))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// 实例名 → 磁盘号标签（首个空格前截断，无空格取全名；
/// 对齐 Go 的 strings.Cut(data.Name, " ")，如 "1 C:" → "1"）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn disk_number(name: &str) -> &str {
    match name.split_once(' ') {
        Some((before, _)) => before,
        None => name,
    }
}

/// 由通配实例样本构造全部 physical_disk 指标族（纯函数，Linux 宿主可测）。
///
/// 发射顺序镜像 Go Collect()：requests_queued → read_bytes → reads →
/// write_bytes → writes → read_seconds → write_seconds → idle_seconds →
/// split_ios → read_latency → write_latency → read_write_latency。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_physical_disk(rows: &[CollectorRow]) -> Vec<MetricFamily> {
    use idx::{
        IDLE_TIME, READ_BYTES, READ_LATENCY, READ_TIME, READ_WRITE_LATENCY, READS, REQUESTS_QUEUED,
        SPLIT_IOS, WRITE_BYTES, WRITE_LATENCY, WRITE_TIME, WRITES,
    };

    // (名称, help, 类型, 计数器索引, 是否为显式 100ns tick 换算)
    let definitions: &[(&str, &str, MetricType, usize, bool)] = &[
        (
            "windows_physical_disk_requests_queued",
            "The number of requests queued to the disk (PhysicalDisk.CurrentDiskQueueLength)",
            MetricType::Gauge,
            REQUESTS_QUEUED,
            false,
        ),
        (
            "windows_physical_disk_read_bytes_total",
            "The number of bytes transferred from the disk during read operations (PhysicalDisk.DiskReadBytesPerSec)",
            MetricType::Counter,
            READ_BYTES,
            false,
        ),
        (
            "windows_physical_disk_reads_total",
            "The number of read operations on the disk (PhysicalDisk.DiskReadsPerSec)",
            MetricType::Counter,
            READS,
            false,
        ),
        (
            "windows_physical_disk_write_bytes_total",
            "The number of bytes transferred to the disk during write operations (PhysicalDisk.DiskWriteBytesPerSec)",
            MetricType::Counter,
            WRITE_BYTES,
            false,
        ),
        (
            "windows_physical_disk_writes_total",
            "The number of write operations on the disk (PhysicalDisk.DiskWritesPerSec)",
            MetricType::Counter,
            WRITES,
            false,
        ),
        (
            "windows_physical_disk_read_seconds_total",
            "Seconds that the disk was busy servicing read requests (PhysicalDisk.PercentDiskReadTime)",
            MetricType::Counter,
            READ_TIME,
            false,
        ),
        (
            "windows_physical_disk_write_seconds_total",
            "Seconds that the disk was busy servicing write requests (PhysicalDisk.PercentDiskWriteTime)",
            MetricType::Counter,
            WRITE_TIME,
            false,
        ),
        (
            "windows_physical_disk_idle_seconds_total",
            "Seconds that the disk was idle (PhysicalDisk.PercentIdleTime)",
            MetricType::Counter,
            IDLE_TIME,
            false,
        ),
        (
            "windows_physical_disk_split_ios_total",
            "The number of I/Os to the disk were split into multiple I/Os (PhysicalDisk.SplitIOPerSec)",
            MetricType::Counter,
            SPLIT_IOS,
            false,
        ),
        (
            "windows_physical_disk_read_latency_seconds_total",
            "Shows the average time, in seconds, of a read operation from the disk (PhysicalDisk.AvgDiskSecPerRead)",
            MetricType::Counter,
            READ_LATENCY,
            true,
        ),
        (
            "windows_physical_disk_write_latency_seconds_total",
            "Shows the average time, in seconds, of a write operation to the disk (PhysicalDisk.AvgDiskSecPerWrite)",
            MetricType::Counter,
            WRITE_LATENCY,
            true,
        ),
        (
            "windows_physical_disk_read_write_latency_seconds_total",
            "Shows the time, in seconds, of the average disk transfer (PhysicalDisk.AvgDiskSecPerTransfer)",
            MetricType::Counter,
            READ_WRITE_LATENCY,
            true,
        ),
    ];

    let mut out = Vec::with_capacity(definitions.len());
    for (name, help, mtype, index, is_latency) in definitions {
        let mut family = MetricFamily::new(name, help, *mtype);
        for row in rows {
            // sample_instanced 已保证全计数器有效，缺项仅可能来自直接调用发射函数的测试
            if let Some(sample) = row.values.get(*index).and_then(Option::as_ref) {
                // 延迟三个计数器为 PERF_AVERAGE_TIMER（raw 原值），显式 ×1e-7；
                // 其余按计数器类型换算（100ns 类型在 raw_to_value 内自动换算）
                let value = if *is_latency {
                    sample.value() * TICKS_TO_SECONDS
                } else {
                    sample.value()
                };
                family.push_labeled(disk_labels(&row.instance), value);
            }
        }
        if !family.samples.is_empty() {
            out.push(family);
        }
    }
    out
}

fn disk_labels(instance: &str) -> Vec<(String, String)> {
    vec![("disk".to_string(), disk_number(instance).to_string())]
}

#[cfg(test)]
mod tests {
    use super::super::RawSample;
    use super::*;

    /// 以原值类型构造样本行
    fn row(instance: &str, first: i64) -> CollectorRow {
        CollectorRow {
            instance: instance.to_string(),
            values: COUNTERS
                .iter()
                .map(|_| {
                    Some(RawSample {
                        first,
                        second: 0,
                        counter_type: 0,
                    })
                })
                .collect(),
        }
    }

    /// 12 个指标族齐全，{disk} 标签取实例名首个空格前截断
    #[test]
    fn test_emit_physical_disk_family_layout() {
        let rows = vec![row("0", 1_000), row("1 C:", 2_000)];
        let families = emit_physical_disk(&rows);

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names.len(), 12, "{names:?}");
        assert_eq!(names[0], "windows_physical_disk_requests_queued");
        assert_eq!(
            names[11],
            "windows_physical_disk_read_write_latency_seconds_total"
        );

        let requests = families
            .iter()
            .find(|family| family.name == "windows_physical_disk_requests_queued")
            .unwrap_or_else(|| panic!("缺少 requests_queued"));
        assert_eq!(requests.mtype, MetricType::Gauge);
        assert_eq!(
            requests.samples[1].labels,
            vec![("disk".to_string(), "1".to_string())]
        );
        assert_eq!(requests.samples[1].value, 2_000.0);
    }

    /// 延迟三个计数器显式 ×1e-7（100ns tick → 秒）
    #[test]
    fn test_latency_scaled() {
        let rows = vec![row("0", 10_000_000)];
        let families = emit_physical_disk(&rows);
        let latency = families
            .iter()
            .find(|family| family.name == "windows_physical_disk_read_latency_seconds_total")
            .unwrap_or_else(|| panic!("缺少 read_latency_seconds_total"));
        assert_eq!(latency.samples[0].value, 1.0);
        // 非延迟计数器原值输出（raw_to_value 对未知类型不换算）
        let reads = families
            .iter()
            .find(|family| family.name == "windows_physical_disk_reads_total")
            .unwrap_or_else(|| panic!("缺少 reads_total"));
        assert_eq!(reads.samples[0].value, 10_000_000.0);
    }

    /// 磁盘号截断：无空格取全名，多空格取首段
    #[test]
    fn test_disk_number() {
        assert_eq!(disk_number("0"), "0");
        assert_eq!(disk_number("1 C:"), "1");
        assert_eq!(disk_number("2 C: mount"), "2");
        assert_eq!(disk_number(""), "");
    }

    /// 计数器清单与索引常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS.len(), 12);
        assert_eq!(COUNTERS[idx::REQUESTS_QUEUED], "Current Disk Queue Length");
        assert_eq!(COUNTERS[idx::READ_WRITE_LATENCY], "Avg. Disk sec/Transfer");
    }
}
