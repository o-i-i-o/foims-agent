//! 采集器实现集合（windows_exporter 移植）。
//!
//! 每个文件对应 windows_exporter 的一个同名采集器（Go 源
//! `internal/collector/<name>/`），指标名称/help/标签/类型逐字对齐。
//!
//! ## raw 值换算语义（对齐 Go internal/pdh/collector.go setRawValue）
//!
//! 全部计数器走 raw 值（CounterTypeRaw）：
//! - `PERF_100NSEC_TIMER` / `PERF_PRECISION_100NS_TIMER`：FirstValue × 1e-7
//!   （100ns tick → 秒，即 Go 的 `TicksToSecondScaleFactor`）；
//! - 其余类型：FirstValue 原值输出（`,secondvalue` 字段取 SecondValue 原值）；
//! - `PERF_ELAPSED_TIME` 需要 Frequency 参与换算，但本 crate 移植的 8 个
//!   采集器（默认启用集）不使用该类型计数器，未实现（见各采集器文档）。
//!
//! 采集器级的显式换算（镜像 Go 采集器代码，如磁盘延迟 ×1e-7）在各文件内
//! 以常量 [`TICKS_TO_SECONDS`] 完成。
//!
//! ## 与 Go 的已知偏离
//! - Go 声明但不输出的 PDH 计数器（如 cpu 的 `C1 Transitions/sec`、memory
//!   的 `Available KBytes`）不再加入 PDH 查询，输出不受影响；
//! - net 采集器仅实现 `metrics` 子采集器，`nic_info`（上游标注
//!   experimental、需 GetAdaptersAddresses 解析链表）跳过；
//! - 有效性过滤仅按 CStatus ∈ {VALID_DATA, NEW_DATA}；实例按
//!   （名称, 出现序号）匹配，Go 的 occurrence 后缀缓存行为未复刻。
//!
//! `build_defaults` 返回默认启用集合（与 windows_exporter 默认配置一致，
//! 共 8 个，按名称字母序，输出顺序稳定便于对照）。

pub mod cpu;
pub mod logical_disk;
pub mod memory;
pub mod net;
pub mod os;
pub mod physical_disk;
pub mod service;
pub mod system;

use std::sync::Arc;

// 以下两项仅 windows 目标使用（PDH 实例匹配 / FFI 错误映射），
// Linux 宿主构建时引用方均被 cfg 掉
#[cfg(target_os = "windows")]
use std::collections::HashMap;

#[cfg(target_os = "windows")]
use crate::ffi;

// CollectorError 仅被 windows 目标的 collector_error 引用
#[cfg_attr(not(target_os = "windows"), allow(unused_imports))]
use foims_agent_core::collector::{Collector, CollectorError};

/// 100ns tick → 秒的换算因子（Go pdh.TicksToSecondScaleFactor = 1/1e7）
pub const TICKS_TO_SECONDS: f64 = 1.0 / 1e7;

/// perflib 计数器类型：PERF_100NSEC_TIMER（winperf.h）
pub const PERF_100NSEC_TIMER: u32 = 0x2051_0500;
/// perflib 计数器类型：PERF_PRECISION_100NS_TIMER（winperf.h / Go const.go
/// 一致为 0x20570500）
pub const PERF_PRECISION_100NS_TIMER: u32 = 0x2057_0500;

/// PDH raw 值状态：有效数据
pub const PDH_CSTATUS_VALID_DATA: u32 = 0x0000_0000;
/// PDH raw 值状态：新数据（同样有效）
pub const PDH_CSTATUS_NEW_DATA: u32 = 0x0000_0001;

/// 单条 raw 计数器读数（对齐 Go pdh.RawCounter 的值字段）
#[derive(Debug, Clone, Copy)]
pub struct RawSample {
    /// FirstValue（大多数类型的值载体）
    pub first: i64,
    /// SecondValue（`,secondvalue` 字段与 PERF_ELAPSED_TIME 使用）
    pub second: i64,
    /// perflib 计数器类型常量（决定换算语义）
    pub counter_type: u32,
}

impl RawSample {
    /// CStatus 是否有效（对齐 Go rowSet 的有效性判定）
    pub fn cstatus_valid(cstatus: u32) -> bool {
        matches!(cstatus, PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA)
    }

    /// 换算 FirstValue 为指标值（镜像 Go setRawValue 的类型分派，
    /// PERF_ELAPSED_TIME 未实现，见模块文档）
    pub fn value(&self) -> f64 {
        raw_to_value(self.counter_type, self.first)
    }

    /// SecondValue 原值（Go default 分支的 secondvalue 字段语义）
    pub fn second_value(&self) -> f64 {
        self.second as f64
    }
}

/// raw FirstValue → 指标值（镜像 Go setRawValue switch）
pub fn raw_to_value(counter_type: u32, first: i64) -> f64 {
    match counter_type {
        PERF_100NSEC_TIMER | PERF_PRECISION_100NS_TIMER => first as f64 * TICKS_TO_SECONDS,
        _ => first as f64,
    }
}

/// u32 回绕差分累计器（对齐 Go utils.Counter：首样本 total=0，
/// 后续 total += uint32 回绕差分，mperf/RTC 指标使用）
#[derive(Debug, Default)]
pub struct WrapCounter {
    last: u32,
    total: f64,
}

/// 通配实例采样的一行（跨平台类型，纯发射函数据此构造指标族）：
/// 实例名 + 各计数器 raw 值（与计数器清单顺序对齐）
#[derive(Debug, Clone)]
pub struct CollectorRow {
    pub instance: String,
    pub values: Vec<Option<RawSample>>,
}

/// FFI 错误 → 采集错误（统一映射，reason 保留原始状态码文本）
#[cfg(target_os = "windows")]
pub(crate) fn collector_error(source: ffi::FfiError) -> CollectorError {
    CollectorError::Parse {
        file: "pdh",
        reason: source.to_string(),
    }
}

impl WrapCounter {
    /// 以首个样本初始化（total=0，与 Go NewCounter 一致）
    pub fn new(first: u32) -> Self {
        Self {
            last: first,
            total: 0.0,
        }
    }

    /// 累加下一个样本（u32 回绕差分）
    pub fn add(&mut self, value: u32) {
        self.total += (value.wrapping_sub(self.last)) as f64;
        self.last = value;
    }

    /// 当前累计值
    pub fn value(&self) -> f64 {
        self.total
    }
}

// PDH 计数器集（仅 windows 目标）

/// 一个 PDH 查询内的一组计数器：构造时全部加入查询，采样时统一 collect。
#[cfg(target_os = "windows")]
pub struct PdhCounterSet {
    query: ffi::PdhQuery,
    counters: Vec<PdhCounterEntry>,
}

#[cfg(target_os = "windows")]
struct PdhCounterEntry {
    counter: ffi::PdhCounter,
    counter_type: u32,
}

#[cfg(target_os = "windows")]
impl PdhCounterSet {
    /// 构建 PDH 计数器集：为 object 下的每个 counter 建
    /// `\{object}\{counter}` 英文计数器路径（支持 `(*)` 通配实例）。
    pub fn new(object: &str, counters: &[&'static str]) -> Result<Self, ffi::FfiError> {
        let mut query = ffi::PdhQuery::open()?;
        let mut entries = Vec::with_capacity(counters.len());
        for name in counters {
            let path = format!("\\{object}\\{name}");
            let counter = query.add_english_counter(&path)?;
            let counter_type = counter.counter_type()?;
            entries.push(PdhCounterEntry {
                counter,
                counter_type,
            });
        }
        Ok(Self {
            query,
            counters: entries,
        })
    }

    /// 采样一次（必须先于读取 raw 值调用）
    pub fn collect(&self) -> Result<(), ffi::FfiError> {
        self.query.collect()
    }

    /// 通配实例采样：按（实例名, 出现序号）匹配各计数器数组，
    /// 某计数器缺失/无效的实例整行丢弃（对齐 Go「全计数器有效才输出」）。
    pub fn sample_instanced(&self) -> Result<Vec<CollectorRow>, ffi::FfiError> {
        let mut rows: Vec<CollectorRow> = Vec::new();
        // (实例名, 出现序号) → 行下标；出现序号在每个计数器数组内独立计数
        let mut index: HashMap<(String, usize), usize> = HashMap::new();
        for (counter_index, entry) in self.counters.iter().enumerate() {
            // 实例名以 owned 形式入表：HashMap 键需跨迭代存活
            let mut occurrence: HashMap<String, usize> = HashMap::new();
            for (name, first, second, cstatus) in entry.counter.raw_array()? {
                if !RawSample::cstatus_valid(cstatus) {
                    continue;
                }
                let seen = occurrence.entry(name.clone()).or_insert(0);
                let key = (name.clone(), *seen);
                *seen += 1;
                let row_index = match index.get(&key) {
                    Some(existing) => *existing,
                    None => {
                        rows.push(CollectorRow {
                            instance: key.0.clone(),
                            values: vec![None; self.counters.len()],
                        });
                        index.insert(key, rows.len() - 1);
                        rows.len() - 1
                    }
                };
                rows[row_index].values[counter_index] = Some(RawSample {
                    first,
                    second,
                    counter_type: entry.counter_type,
                });
            }
        }
        // 全计数器均有有效值的实例才输出
        Ok(rows
            .into_iter()
            .filter(|row| row.values.iter().all(Option::is_some))
            .collect())
    }

    /// 单实例对象采样：各计数器的 raw 值按声明顺序排列；
    /// 任一计数器无效则返回 None（对齐 Go 的整行丢弃语义）。
    pub fn sample_single(&self) -> Result<Option<Vec<RawSample>>, ffi::FfiError> {
        let mut out = Vec::with_capacity(self.counters.len());
        for entry in &self.counters {
            let (first, second, cstatus) = entry.counter.raw_single()?;
            if !RawSample::cstatus_valid(cstatus) {
                return Ok(None);
            }
            out.push(RawSample {
                first,
                second,
                counter_type: entry.counter_type,
            });
        }
        Ok(Some(out))
    }
}

/// 构建默认启用的采集器实例集合（按名称字母序，输出顺序稳定便于对照；
/// 与 windows_exporter pkg/collector/types.go 的 DefaultCollectors 一致）。
pub fn build_defaults() -> Vec<Arc<dyn Collector>> {
    vec![
        Arc::new(cpu::CpuCollector::new()),
        Arc::new(logical_disk::LogicalDiskCollector::new()),
        Arc::new(memory::MemoryCollector::new()),
        Arc::new(net::NetCollector::new()),
        Arc::new(os::OsCollector::new()),
        Arc::new(physical_disk::PhysicalDiskCollector::new()),
        Arc::new(service::ServiceCollector::new()),
        Arc::new(system::SystemCollector::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 100ns 类型换算为秒，其余类型原值输出
    #[test]
    fn test_raw_to_value() {
        // PERF_100NSEC_TIMER：1e7 tick = 1 秒
        assert_eq!(raw_to_value(PERF_100NSEC_TIMER, 10_000_000), 1.0);
        assert_eq!(
            raw_to_value(PERF_PRECISION_100NS_TIMER, 123_456_789),
            12.3456789
        );
        // 其余类型原值（含负值）
        assert_eq!(raw_to_value(0x0000_0000, 42), 42.0);
        assert_eq!(raw_to_value(0x3002_0400, -7), -7.0);
        assert_eq!(TICKS_TO_SECONDS, 1e-7);
    }

    /// WrapCounter：首样本 total=0，回绕差分正确累计
    #[test]
    fn test_wrap_counter() {
        let mut counter = WrapCounter::new(100);
        assert_eq!(counter.value(), 0.0);
        counter.add(150);
        assert_eq!(counter.value(), 50.0);
        // u32 回绕：u32::MAX → 0 的差分应 +1
        let mut wrap = WrapCounter::new(u32::MAX - 2);
        wrap.add(u32::MAX);
        assert_eq!(wrap.value(), 2.0);
        wrap.add(1);
        assert_eq!(wrap.value(), 4.0);
    }

    /// RawSample 辅助方法
    #[test]
    fn test_raw_sample_helpers() {
        let sample = RawSample {
            first: 5_000_000_000,
            second: 9,
            counter_type: PERF_100NSEC_TIMER,
        };
        assert_eq!(sample.value(), 500.0);
        assert_eq!(sample.second_value(), 9.0);
        assert!(RawSample::cstatus_valid(0));
        assert!(RawSample::cstatus_valid(1));
        assert!(!RawSample::cstatus_valid(0xC000_0BBC));
    }
}
