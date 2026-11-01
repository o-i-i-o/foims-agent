//! system 采集器（对齐 Go `internal/collector/system/`）。
//!
//! PDH 对象 `System`（单实例，6 个计数器）+ 开机时刻，共 8 个指标族
//! （boot_time_timestamp / context_switches_total / exception_dispatches_total
//! / processor_queue_length / processes / processes_limit / system_calls_total
//! / threads）。
//!
//! 与 Go 的偏离：
//! - 开机时刻：Go 用 ntdll.BootTime（内核真实启动时刻，随时钟校正移动）；
//!   本实现以「当前 Unix 秒 − GetTickCount64 毫秒/1000」推导（两边均取整秒，
//!   亚秒级时钟校正对整秒值无影响），省去 ntdll FFI；
//! - Go 的 PDH 失败路径仍保留 boot_time 指标（逐条发射），本 crate 采集器
//!   为 Result 全有或全无语义，PDH 失败时整轮失败。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::RawSample;

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 顺序即索引约定，勿调整）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "Context Switches/sec",
    "Exception Dispatches/sec",
    "Processor Queue Length",
    "System Calls/sec",
    "Processes",
    "Threads",
];

// 上述清单的索引常量（采集器取值用；跨平台供发射函数与测试引用）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const CONTEXT_SWITCHES: usize = 0;
    pub(super) const EXCEPTION_DISPATCHES: usize = 1;
    pub(super) const PROCESSOR_QUEUE_LENGTH: usize = 2;
    pub(super) const SYSTEM_CALLS: usize = 3;
    pub(super) const PROCESSES: usize = 4;
    pub(super) const THREADS: usize = 5;
}

/// system 采集器：持有单实例 PDH 计数器集
pub struct SystemCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
}

impl SystemCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("System", COUNTERS) {
                Ok(set) => Self { set: Some(set) },
                // PDH 初始化失败时保留空集，collect 时按 NoData 上报，
                // 保证单采集器故障不拖垮其余采集器
                Err(error) => {
                    tracing::warn!(%error, "system 采集器 PDH 初始化失败");
                    Self { set: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        match &self.set {
            None => Err(CollectorError::NoData),
            Some(set) => {
                set.collect().map_err(super::collector_error)?;
                let sample = set
                    .sample_single()
                    .map_err(super::collector_error)?
                    .ok_or(CollectorError::NoData)?;
                Ok(emit_system(&sample, boot_time_timestamp()))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// 当前 Unix 秒（SystemTime 距 epoch 的整秒；时钟早于 1970 时按 0）
#[cfg(target_os = "windows")]
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// 开机时刻（Unix 秒）= 当前 Unix 秒 − GetTickCount64 毫秒/1000
#[cfg(target_os = "windows")]
fn boot_time_timestamp() -> f64 {
    boot_time_secs(unix_now_secs(), crate::ffi::tick_count_millis()) as f64
}

/// 纯函数：开机时刻推导（整秒减法，时钟回拨时取 0 下界）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn boot_time_secs(now_unix_secs: u64, tick_count_millis: u64) -> u64 {
    now_unix_secs.saturating_sub(tick_count_millis / 1000)
}

/// 由单实例样本构造全部 system 指标族（纯函数，Linux 宿主可测）。
///
/// 发射顺序镜像 Go Collect()：boot_time → context_switches →
/// exception_dispatches → processor_queue_length → processes →
/// system_calls → threads → processes_limit。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_system(sample: &[RawSample], boot_time_secs: f64) -> Vec<MetricFamily> {
    use idx::{
        CONTEXT_SWITCHES, EXCEPTION_DISPATCHES, PROCESSES, PROCESSOR_QUEUE_LENGTH, SYSTEM_CALLS,
        THREADS,
    };

    // (名称, help, 类型, 计数器索引)
    let definitions: &[(&str, &str, MetricType, usize)] = &[
        (
            "windows_system_context_switches_total",
            "Total number of context switches",
            MetricType::Counter,
            CONTEXT_SWITCHES,
        ),
        (
            "windows_system_exception_dispatches_total",
            "Total number of exceptions dispatched",
            MetricType::Counter,
            EXCEPTION_DISPATCHES,
        ),
        (
            "windows_system_processor_queue_length",
            "Length of processor queue",
            MetricType::Gauge,
            PROCESSOR_QUEUE_LENGTH,
        ),
        (
            "windows_system_processes",
            "Current number of processes",
            MetricType::Gauge,
            PROCESSES,
        ),
        (
            "windows_system_system_calls_total",
            "Total number of system calls",
            MetricType::Counter,
            SYSTEM_CALLS,
        ),
        (
            "windows_system_threads",
            "Current number of threads",
            MetricType::Gauge,
            THREADS,
        ),
    ];

    let mut boot_time = MetricFamily::new(
        "windows_system_boot_time_timestamp",
        "Unix timestamp of last system boot. Follows clock corrections.",
        MetricType::Gauge,
    );
    boot_time.push(boot_time_secs);

    let mut out = vec![boot_time];
    for (name, help, mtype, index) in definitions {
        let mut family = MetricFamily::new(name, help, *mtype);
        if let Some(raw) = sample.get(*index) {
            family.push(raw.value());
        }
        if !family.samples.is_empty() {
            out.push(family);
        }
    }

    // Windows 未定义进程数上限（内核按资源动态分配，WMI 不计算，取默认值）
    let mut processes_limit = MetricFamily::new(
        "windows_system_processes_limit",
        "Maximum number of processes.",
        MetricType::Gauge,
    );
    processes_limit.push(4_294_967_295.0);
    out.push(processes_limit);
    out
}

#[cfg(test)]
mod tests {
    use super::super::RawSample;
    use super::*;

    /// 以原值类型构造单实例样本
    fn sample(first: i64) -> Vec<RawSample> {
        COUNTERS
            .iter()
            .map(|_| RawSample {
                first,
                second: 0,
                counter_type: 0,
            })
            .collect()
    }

    /// 8 个指标族齐全，顺序与类型正确
    #[test]
    fn test_emit_system_family_layout() {
        let families = emit_system(&sample(42), 1_700_000_000.0);

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names.len(), 8, "{names:?}");
        assert_eq!(names[0], "windows_system_boot_time_timestamp");
        assert_eq!(names[1], "windows_system_context_switches_total");
        assert_eq!(names[7], "windows_system_processes_limit");

        let boot = &families[0];
        assert_eq!(boot.mtype, MetricType::Gauge);
        assert_eq!(boot.samples[0].value, 1_700_000_000.0);

        let switches = families
            .iter()
            .find(|family| family.name == "windows_system_context_switches_total")
            .unwrap_or_else(|| panic!("缺少 context_switches_total"));
        assert_eq!(switches.mtype, MetricType::Counter);
        assert_eq!(switches.samples[0].value, 42.0);

        let limit = families
            .iter()
            .find(|family| family.name == "windows_system_processes_limit")
            .unwrap_or_else(|| panic!("缺少 processes_limit"));
        assert_eq!(limit.samples[0].value, 4_294_967_295.0);
    }

    /// 开机时刻推导：整秒差分，时钟回拨取 0
    #[test]
    fn test_boot_time_secs() {
        assert_eq!(boot_time_secs(1_700_000_100, 100_000), 1_700_000_000);
        // 亚秒毫秒被截断（100ms → 0 秒）
        assert_eq!(boot_time_secs(1_000_000_000, 500), 1_000_000_000);
        // 时钟早于开机时刻（回拨）→ 0
        assert_eq!(boot_time_secs(100, 100_000), 0);
    }

    /// 计数器清单与索引常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS.len(), 6);
        assert_eq!(COUNTERS[idx::CONTEXT_SWITCHES], "Context Switches/sec");
        assert_eq!(COUNTERS[idx::THREADS], "Threads");
    }
}
