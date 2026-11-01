//! cpu 采集器（对齐 Go `internal/collector/cpu/`）。
//!
//! PDH 对象 `Processor Information`，通配实例；输出 14 个指标族
//! （cstate_seconds_total / time_total / interrupts_total / dpcs_total /
//! clock_interrupts_total / idle_break_events_total / parking_status /
//! core_frequency_mhz / processor_performance_total / processor_mperf_total /
//! processor_rtc_total / processor_utility_total /
//! processor_privileged_utility_total / logical_processor）。
//!
//! 与 Go 的偏离：
//! - Go 声明但不输出的计数器（`C1/C2/C3 Transitions/sec`、
//!   `% Performance Limit`、`% Priority Time`、`% Processor Time`）不加入
//!   PDH 查询，输出不受影响；
//! - mperf/RTC 的 secondvalue 经 `uint32` 截断后按回绕差分累计
//!   （Go utils.Counter 语义，见 [`super::WrapCounter`]）；
//! - `logical_processor` 计数为实例行数（含 `_Total`，与 Go coreCount++
//!   逐字一致，属上游行为）。

use std::collections::HashMap;
// Mutex 仅被 windows 目标的累计器字段使用
#[cfg(target_os = "windows")]
use std::sync::Mutex;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::{CollectorRow, WrapCounter};

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 仅保留实际输出的计数器；顺序即索引约定，勿调整）
/// Linux 宿主非测试构建中仅被发射函数（已允许 dead_code）引用
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "% C1 Time",
    "% C2 Time",
    "% C3 Time",
    "Clock Interrupts/sec",
    "DPCs Queued/sec",
    "% DPC Time",
    "Idle Break Events/sec",
    "% Idle Time",
    "Interrupts/sec",
    "% Interrupt Time",
    "Parking Status",
    "% Privileged Time",
    "% Privileged Utility",
    "Processor Frequency",
    "% Processor Performance",
    "% Processor Utility",
    "% User Time",
];

// 上述清单的索引常量（采集器取值用；跨平台供发射函数与测试引用）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const C1: usize = 0;
    pub(super) const C2: usize = 1;
    pub(super) const C3: usize = 2;
    pub(super) const CLOCK_INTERRUPTS: usize = 3;
    pub(super) const DPCS: usize = 4;
    pub(super) const DPC_TIME: usize = 5;
    pub(super) const IDLE_BREAK_EVENTS: usize = 6;
    pub(super) const IDLE_TIME: usize = 7;
    pub(super) const INTERRUPTS: usize = 8;
    pub(super) const INTERRUPT_TIME: usize = 9;
    pub(super) const PARKING_STATUS: usize = 10;
    pub(super) const PRIVILEGED_TIME: usize = 11;
    pub(super) const PRIVILEGED_UTILITY: usize = 12;
    pub(super) const CORE_FREQUENCY: usize = 13;
    pub(super) const PROCESSOR_PERFORMANCE: usize = 14;
    pub(super) const PROCESSOR_UTILITY: usize = 15;
    pub(super) const USER_TIME: usize = 16;
}

/// cpu 采集器：持有 PDH 计数器集与 mperf/RTC 回绕累计器
pub struct CpuCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
    /// processor_rtc_total 累计器（key = 实例名）
    #[cfg(target_os = "windows")]
    rtc_values: Mutex<HashMap<String, WrapCounter>>,
    /// processor_mperf_total 累计器（key = 实例名）
    #[cfg(target_os = "windows")]
    mperf_values: Mutex<HashMap<String, WrapCounter>>,
}

impl CpuCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("Processor Information", COUNTERS) {
                Ok(set) => Self {
                    set: Some(set),
                    rtc_values: Mutex::new(HashMap::new()),
                    mperf_values: Mutex::new(HashMap::new()),
                },
                // PDH 初始化失败时保留空集，collect 时按 NoData 上报，
                // 保证单采集器故障不拖垮其余采集器
                Err(error) => {
                    tracing::warn!(%error, "cpu 采集器 PDH 初始化失败");
                    Self::empty()
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self::empty()
    }

    /// 空采集器（非 windows 目标 / 初始化失败）
    fn empty() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self {
                set: None,
                rtc_values: Mutex::new(HashMap::new()),
                mperf_values: Mutex::new(HashMap::new()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for CpuCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        match &self.set {
            None => Err(CollectorError::NoData),
            Some(set) => {
                set.collect().map_err(super::collector_error)?;
                let rows = set.sample_instanced().map_err(super::collector_error)?;
                // 中毒视为不可恢复异常之外的场景：取回内部数据继续工作
                let mut rtc = self
                    .rtc_values
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut mperf = self
                    .mperf_values
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                Ok(emit_cpu(&rows, &mut rtc, &mut mperf))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// 由通配实例样本构造全部 cpu 指标族（纯函数，Linux 宿主可测）。
///
/// 累计器按实例名维护，首样本 total=0（Go utils.Counter 语义）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_cpu(
    rows: &[CollectorRow],
    rtc_values: &mut HashMap<String, WrapCounter>,
    mperf_values: &mut HashMap<String, WrapCounter>,
) -> Vec<MetricFamily> {
    use idx::{
        C1, C2, C3, CLOCK_INTERRUPTS, CORE_FREQUENCY, DPC_TIME, DPCS, IDLE_BREAK_EVENTS, IDLE_TIME,
        INTERRUPT_TIME, INTERRUPTS, PARKING_STATUS, PRIVILEGED_TIME, PRIVILEGED_UTILITY,
        PROCESSOR_PERFORMANCE, PROCESSOR_UTILITY, USER_TIME,
    };

    let mut cstate = MetricFamily::new(
        "windows_cpu_cstate_seconds_total",
        "Time spent in low-power idle state",
        MetricType::Counter,
    );
    let mut time_total = MetricFamily::new(
        "windows_cpu_time_total",
        "Time that processor spent in different modes (dpc, idle, interrupt, privileged, user)",
        MetricType::Counter,
    );
    let mut interrupts = MetricFamily::new(
        "windows_cpu_interrupts_total",
        "Total number of received and serviced hardware interrupts",
        MetricType::Counter,
    );
    let mut dpcs = MetricFamily::new(
        "windows_cpu_dpcs_total",
        "Total number of received and serviced deferred procedure calls (DPCs)",
        MetricType::Counter,
    );
    let mut clock_interrupts = MetricFamily::new(
        "windows_cpu_clock_interrupts_total",
        "Total number of received and serviced clock tick interrupts",
        MetricType::Counter,
    );
    let mut idle_break_events = MetricFamily::new(
        "windows_cpu_idle_break_events_total",
        "Total number of time processor was woken from idle",
        MetricType::Counter,
    );
    let mut parking = MetricFamily::new(
        "windows_cpu_parking_status",
        "Parking Status represents whether a processor is parked or not",
        MetricType::Gauge,
    );
    let mut frequency = MetricFamily::new(
        "windows_cpu_core_frequency_mhz",
        "Core frequency in megahertz",
        MetricType::Gauge,
    );
    let mut performance = MetricFamily::new(
        "windows_cpu_processor_performance_total",
        "Processor Performance is the average performance of the processor while it is executing instructions, as a percentage of the nominal performance of the processor. On some processors, Processor Performance may exceed 100%",
        MetricType::Counter,
    );
    let mut mperf = MetricFamily::new(
        "windows_cpu_processor_mperf_total",
        "Processor MPerf is the number of TSC ticks incremented while executing instructions",
        MetricType::Counter,
    );
    let mut rtc = MetricFamily::new(
        "windows_cpu_processor_rtc_total",
        "Processor RTC represents the number of RTC ticks made since the system booted. It should consistently be 64e6, and can be used to properly derive Processor Utility Rate",
        MetricType::Counter,
    );
    let mut utility = MetricFamily::new(
        "windows_cpu_processor_utility_total",
        "Processor Utility represents is the amount of time the core spends executing instructions",
        MetricType::Counter,
    );
    let mut privileged_utility = MetricFamily::new(
        "windows_cpu_processor_privileged_utility_total",
        "Processor Privileged Utility represents is the amount of time the core has spent executing instructions inside the kernel",
        MetricType::Counter,
    );

    let core_label = |name: &str| vec![("core".to_string(), name.to_string())];

    for row in rows {
        let core = row.instance.as_str();
        // sample_instanced 已保证全计数器有效，缺项仅可能来自直接调用发射函数的测试
        if let Some(sample) = row.values.get(C1).and_then(Option::as_ref) {
            cstate.push_labeled(labeled_core_state(core, "c1"), sample.value());
        }
        if let Some(sample) = row.values.get(C2).and_then(Option::as_ref) {
            cstate.push_labeled(labeled_core_state(core, "c2"), sample.value());
        }
        if let Some(sample) = row.values.get(C3).and_then(Option::as_ref) {
            cstate.push_labeled(labeled_core_state(core, "c3"), sample.value());
        }

        if let Some(sample) = row.values.get(IDLE_TIME).and_then(Option::as_ref) {
            time_total.push_labeled(labeled_core_mode(core, "idle"), sample.value());
        }
        if let Some(sample) = row.values.get(INTERRUPT_TIME).and_then(Option::as_ref) {
            time_total.push_labeled(labeled_core_mode(core, "interrupt"), sample.value());
        }
        if let Some(sample) = row.values.get(DPC_TIME).and_then(Option::as_ref) {
            time_total.push_labeled(labeled_core_mode(core, "dpc"), sample.value());
        }
        if let Some(sample) = row.values.get(PRIVILEGED_TIME).and_then(Option::as_ref) {
            time_total.push_labeled(labeled_core_mode(core, "privileged"), sample.value());
        }
        if let Some(sample) = row.values.get(USER_TIME).and_then(Option::as_ref) {
            time_total.push_labeled(labeled_core_mode(core, "user"), sample.value());
        }

        if let Some(sample) = row.values.get(INTERRUPTS).and_then(Option::as_ref) {
            interrupts.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(DPCS).and_then(Option::as_ref) {
            dpcs.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(CLOCK_INTERRUPTS).and_then(Option::as_ref) {
            clock_interrupts.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(IDLE_BREAK_EVENTS).and_then(Option::as_ref) {
            idle_break_events.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(PARKING_STATUS).and_then(Option::as_ref) {
            parking.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(CORE_FREQUENCY).and_then(Option::as_ref) {
            frequency.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row
            .values
            .get(PROCESSOR_PERFORMANCE)
            .and_then(Option::as_ref)
        {
            performance.push_labeled(core_label(core), sample.value());

            // mperf："% Processor Performance,secondvalue"（u32 截断 + 回绕累计）
            let mperf_sample = wrap_add(mperf_values, core, sample.second);
            mperf.push_labeled(core_label(core), mperf_sample);
        }
        if let Some(sample) = row.values.get(PROCESSOR_UTILITY).and_then(Option::as_ref) {
            // rtc："% Processor Utility,secondvalue"
            let rtc_sample = wrap_add(rtc_values, core, sample.second);
            rtc.push_labeled(core_label(core), rtc_sample);

            utility.push_labeled(core_label(core), sample.value());
        }
        if let Some(sample) = row.values.get(PRIVILEGED_UTILITY).and_then(Option::as_ref) {
            privileged_utility.push_labeled(core_label(core), sample.value());
        }
    }

    let mut logical_processors = MetricFamily::new(
        "windows_cpu_logical_processor",
        "Total number of logical processors",
        MetricType::Gauge,
    );
    // 计数为实例行数（含 _Total，镜像 Go coreCount++ 行为）
    logical_processors.push(rows.len() as f64);

    let mut out = Vec::new();
    for family in [
        cstate,
        time_total,
        interrupts,
        dpcs,
        clock_interrupts,
        idle_break_events,
        parking,
        frequency,
        performance,
        mperf,
        rtc,
        utility,
        privileged_utility,
    ] {
        if !family.samples.is_empty() {
            out.push(family);
        }
    }
    out.push(logical_processors);
    out
}

/// mperf/RTC 回绕累计：已存在的实例累加，新实例以当前值初始化（total=0）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn wrap_add(accumulators: &mut HashMap<String, WrapCounter>, core: &str, second: i64) -> f64 {
    let value = second as u32;
    match accumulators.get_mut(core) {
        Some(counter) => {
            counter.add(value);
            counter.value()
        }
        None => {
            accumulators.insert(core.to_string(), WrapCounter::new(value));
            0.0
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn labeled_core_state(core: &str, state: &str) -> Vec<(String, String)> {
    vec![
        ("core".to_string(), core.to_string()),
        ("state".to_string(), state.to_string()),
    ]
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn labeled_core_mode(core: &str, mode: &str) -> Vec<(String, String)> {
    vec![
        ("core".to_string(), core.to_string()),
        ("mode".to_string(), mode.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::super::RawSample;
    use super::*;

    /// 以 100ns 类型构造样本行
    fn row(instance: &str, ticks: i64, second: i64) -> CollectorRow {
        CollectorRow {
            instance: instance.to_string(),
            values: COUNTERS
                .iter()
                .map(|_| {
                    Some(RawSample {
                        first: ticks,
                        second,
                        counter_type: super::super::PERF_100NSEC_TIMER,
                    })
                })
                .collect(),
        }
    }

    /// 14 个指标族齐全，100ns tick 换算为秒，逻辑处理器计数含 _Total 行
    #[test]
    fn test_emit_cpu_family_layout() {
        let rows = vec![row("0,0", 100_000_000, 7), row("_Total", 200_000_000, 9)];
        let mut rtc = HashMap::new();
        let mut mperf = HashMap::new();
        let families = emit_cpu(&rows, &mut rtc, &mut mperf);

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names.len(), 14, "{names:?}");
        assert!(names.contains(&"windows_cpu_cstate_seconds_total"));
        assert!(names.contains(&"windows_cpu_time_total"));
        assert!(names.contains(&"windows_cpu_logical_processor"));

        // 100ns tick → 秒
        let time = families
            .iter()
            .find(|family| family.name == "windows_cpu_time_total")
            .unwrap_or_else(|| panic!("缺少 time_total"));
        assert_eq!(time.mtype, MetricType::Counter);
        // 2 行 × 5 模式
        assert_eq!(time.samples.len(), 10);
        let idle = time
            .samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(k, v)| k == "mode" && v == "idle")
            })
            .unwrap_or_else(|| panic!("缺少 idle 模式"));
        assert_eq!(idle.value, 10.0);

        // logical_processor 计数为行数（含 _Total，镜像 Go）
        let logical = families
            .iter()
            .find(|family| family.name == "windows_cpu_logical_processor")
            .unwrap_or_else(|| panic!("缺少 logical_processor"));
        assert_eq!(logical.mtype, MetricType::Gauge);
        assert_eq!(logical.samples.len(), 1);
        assert_eq!(logical.samples[0].value, 2.0);
    }

    /// mperf/RTC 首样本 total=0，后续回绕差分累计
    #[test]
    fn test_mperf_rtc_accumulation() {
        let mut rtc = HashMap::new();
        let mut mperf = HashMap::new();
        let rows = vec![row("0,0", 10_000_000, 100)];
        let families = emit_cpu(&rows, &mut rtc, &mut mperf);
        let mperf_family = families
            .iter()
            .find(|family| family.name == "windows_cpu_processor_mperf_total")
            .unwrap_or_else(|| panic!("缺少 mperf"));
        let rtc_family = families
            .iter()
            .find(|family| family.name == "windows_cpu_processor_rtc_total")
            .unwrap_or_else(|| panic!("缺少 rtc"));
        // 首样本 total=0
        assert_eq!(mperf_family.samples[0].value, 0.0);
        assert_eq!(rtc_family.samples[0].value, 0.0);

        // 第二样本差分 25
        let rows = vec![row("0,0", 20_000_000, 125)];
        let families = emit_cpu(&rows, &mut rtc, &mut mperf);
        let mperf_family = families
            .iter()
            .find(|family| family.name == "windows_cpu_processor_mperf_total")
            .unwrap_or_else(|| panic!("缺少 mperf"));
        assert_eq!(mperf_family.samples[0].value, 25.0);

        // 换实例后重新从 0 起算
        let rows = vec![row("0,1", 30_000_000, 5)];
        let families = emit_cpu(&rows, &mut rtc, &mut mperf);
        let mperf_family = families
            .iter()
            .find(|family| family.name == "windows_cpu_processor_mperf_total")
            .unwrap_or_else(|| panic!("缺少 mperf"));
        assert_eq!(mperf_family.samples[0].value, 0.0);
    }

    /// COUNTERS 清单索引与 idx 常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS[idx::C1], "% C1 Time");
        assert_eq!(COUNTERS[idx::USER_TIME], "% User Time");
        assert_eq!(COUNTERS.len(), 17);
    }
}
