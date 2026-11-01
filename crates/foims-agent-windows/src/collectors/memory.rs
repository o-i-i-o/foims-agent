//! memory 采集器（对齐 Go `internal/collector/memory/`）。
//!
//! PDH 对象 `Memory`（单实例，32 个计数器）+ `GlobalMemoryStatusEx`
//! （3 个指标），共 35 个指标族。
//!
//! 与 Go 的偏离：
//! - Go 声明但不输出的 `Available KBytes` / `Available MBytes` 计数器
//!   不加入 PDH 查询，输出不受影响；
//! - `pool_nonpaged_allocs_total` 为 Gauge、`pool_paged_allocs_total` 为
//!   Counter —— 与 Go 逐字一致（上游即如此声明）。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::RawSample;

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 仅保留实际输出的 32 个；顺序即索引约定，勿调整）
/// Linux 宿主非测试构建中仅被发射函数（已允许 dead_code）引用
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "Available Bytes",
    "Cache Bytes",
    "Cache Bytes Peak",
    "Cache Faults/sec",
    "Commit Limit",
    "Committed Bytes",
    "Demand Zero Faults/sec",
    "Free & Zero Page List Bytes",
    "Long-Term Average Standby Cache Lifetime (s)",
    "Modified Page List Bytes",
    "Page Faults/sec",
    "Page Reads/sec",
    "Pages Input/sec",
    "Pages Output/sec",
    "Pages/sec",
    "Page Writes/sec",
    "Pool Nonpaged Allocs",
    "Pool Nonpaged Bytes",
    "Pool Paged Allocs",
    "Pool Paged Bytes",
    "Pool Paged Resident Bytes",
    "Standby Cache Core Bytes",
    "Standby Cache Normal Priority Bytes",
    "Standby Cache Reserve Bytes",
    "System Cache Resident Bytes",
    "System Code Resident Bytes",
    "System Code Total Bytes",
    "System Driver Resident Bytes",
    "System Driver Total Bytes",
    "Transition Faults/sec",
    "Transition Pages RePurposed/sec",
    "Write Copies/sec",
];

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const AVAILABLE: usize = 0;
    pub(super) const CACHE: usize = 1;
    pub(super) const CACHE_PEAK: usize = 2;
    pub(super) const CACHE_FAULTS: usize = 3;
    pub(super) const COMMIT_LIMIT: usize = 4;
    pub(super) const COMMITTED: usize = 5;
    pub(super) const DEMAND_ZERO_FAULTS: usize = 6;
    pub(super) const FREE_AND_ZERO_PAGE_LIST: usize = 7;
    pub(super) const STANDBY_LIFETIME: usize = 8;
    pub(super) const MODIFIED_PAGE_LIST: usize = 9;
    pub(super) const PAGE_FAULTS: usize = 10;
    pub(super) const PAGE_READS: usize = 11;
    pub(super) const PAGES_INPUT: usize = 12;
    pub(super) const PAGES_OUTPUT: usize = 13;
    pub(super) const PAGES: usize = 14;
    pub(super) const PAGE_WRITES: usize = 15;
    pub(super) const POOL_NONPAGED_ALLOCS: usize = 16;
    pub(super) const POOL_NONPAGED: usize = 17;
    pub(super) const POOL_PAGED_ALLOCS: usize = 18;
    pub(super) const POOL_PAGED: usize = 19;
    pub(super) const POOL_PAGED_RESIDENT: usize = 20;
    pub(super) const STANDBY_CORE: usize = 21;
    pub(super) const STANDBY_NORMAL: usize = 22;
    pub(super) const STANDBY_RESERVE: usize = 23;
    pub(super) const SYSTEM_CACHE_RESIDENT: usize = 24;
    pub(super) const SYSTEM_CODE_RESIDENT: usize = 25;
    pub(super) const SYSTEM_CODE_TOTAL: usize = 26;
    pub(super) const SYSTEM_DRIVER_RESIDENT: usize = 27;
    pub(super) const SYSTEM_DRIVER_TOTAL: usize = 28;
    pub(super) const TRANSITION_FAULTS: usize = 29;
    pub(super) const TRANSITION_REPURPOSED: usize = 30;
    pub(super) const WRITE_COPIES: usize = 31;
}

/// memory 采集器：持有单实例 PDH 计数器集
pub struct MemoryCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
}

impl MemoryCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("Memory", COUNTERS) {
                Ok(set) => Self { set: Some(set) },
                Err(error) => {
                    tracing::warn!(%error, "memory 采集器 PDH 初始化失败");
                    Self { set: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for MemoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str {
        "memory"
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
                Ok(emit_memory(
                    &sample,
                    crate::ffi::global_memory_status()
                        .ok()
                        .map(MemorySnapshot::from),
                ))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// GlobalMemoryStatusEx 快照（跨平台纯数据：windows 目标由 ffi 填充，
/// Linux 宿主测试直接构造，避免依赖被 cfg 整体裁剪的 ffi 模块）
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MemorySnapshot {
    /// 物理内存总量（字节）
    pub total_phys: u64,
    /// 可用物理内存（字节）
    pub avail_phys: u64,
    /// 用户态虚拟地址空间总量（字节）
    pub total_virtual: u64,
}

#[cfg(target_os = "windows")]
impl From<crate::ffi::MemoryStatus> for MemorySnapshot {
    fn from(status: crate::ffi::MemoryStatus) -> Self {
        Self {
            total_phys: status.total_phys,
            avail_phys: status.avail_phys,
            total_virtual: status.total_virtual,
        }
    }
}

/// 指标族定义表：(名称, help, 类型, 对应计数器索引)。
/// help 与类型逐字对齐 Go memory.go（含上游 pool allocs 的 Gauge/Counter
/// 声明差异）；`None` 表示 GlobalMemoryStatusEx 来源。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const FAMILIES: &[(&str, &str, MetricType, Option<usize>)] = &[
    (
        "windows_memory_available_bytes",
        "The amount of physical memory immediately available for allocation to a process or for system use. It is equal to the sum of memory assigned to the standby (cached), free and zero page lists (AvailableBytes)",
        MetricType::Gauge,
        Some(idx::AVAILABLE),
    ),
    (
        "windows_memory_cache_bytes",
        "(CacheBytes)",
        MetricType::Gauge,
        Some(idx::CACHE),
    ),
    (
        "windows_memory_cache_bytes_peak",
        "(CacheBytesPeak)",
        MetricType::Gauge,
        Some(idx::CACHE_PEAK),
    ),
    (
        "windows_memory_cache_faults_total",
        "Number of faults which occur when a page sought in the file system cache is not found there and must be retrieved from elsewhere in memory (soft fault) or from disk (hard fault) (Cache Faults/sec)",
        MetricType::Counter,
        Some(idx::CACHE_FAULTS),
    ),
    (
        "windows_memory_commit_limit_bytes",
        "Amount of virtual memory, in bytes, that can be committed without having to extend the paging file(s) (CommitLimit)",
        MetricType::Gauge,
        Some(idx::COMMIT_LIMIT),
    ),
    (
        "windows_memory_committed_bytes",
        "(CommittedBytes)",
        MetricType::Gauge,
        Some(idx::COMMITTED),
    ),
    (
        "windows_memory_demand_zero_faults_total",
        "The number of zeroed pages required to satisfy faults. Zeroed pages, pages emptied of previously stored data and filled with zeros, are a security feature of Windows that prevent processes from seeing data stored by earlier processes that used the memory space (Demand Zero Faults/sec)",
        MetricType::Counter,
        Some(idx::DEMAND_ZERO_FAULTS),
    ),
    (
        "windows_memory_free_and_zero_page_list_bytes",
        "The amount of physical memory, in bytes, that is assigned to the free and zero page lists. This memory does not contain cached data. It is immediately available for allocation to a process or for system use (FreeAndZeroPageListBytes)",
        MetricType::Gauge,
        Some(idx::FREE_AND_ZERO_PAGE_LIST),
    ),
    (
        "windows_memory_modified_page_list_bytes",
        "The amount of physical memory, in bytes, that is assigned to the modified page list. This memory contains cached data and code that is not actively in use by processes, the system and the system cache (ModifiedPageListBytes)",
        MetricType::Gauge,
        Some(idx::MODIFIED_PAGE_LIST),
    ),
    (
        "windows_memory_page_faults_total",
        "Overall rate at which faulted pages are handled by the processor (Page Faults/sec)",
        MetricType::Counter,
        Some(idx::PAGE_FAULTS),
    ),
    (
        "windows_memory_swap_page_reads_total",
        "Number of disk page reads (a single read operation reading several pages is still only counted once) (PageReadsPerSec)",
        MetricType::Counter,
        Some(idx::PAGE_READS),
    ),
    (
        "windows_memory_swap_pages_read_total",
        "Number of pages read across all page reads (ie counting all pages read even if they are read in a single operation) (PagesInputPerSec)",
        MetricType::Counter,
        Some(idx::PAGES_INPUT),
    ),
    (
        "windows_memory_swap_pages_written_total",
        "Number of pages written across all page writes (ie counting all pages written even if they are written in a single operation) (PagesOutputPerSec)",
        MetricType::Counter,
        Some(idx::PAGES_OUTPUT),
    ),
    (
        "windows_memory_swap_page_operations_total",
        "Total number of swap page read and writes (PagesPerSec)",
        MetricType::Counter,
        Some(idx::PAGES),
    ),
    (
        "windows_memory_swap_page_writes_total",
        "Number of disk page writes (a single write operation writing several pages is still only counted once) (PageWritesPerSec)",
        MetricType::Counter,
        Some(idx::PAGE_WRITES),
    ),
    (
        "windows_memory_pool_nonpaged_allocs_total",
        "The number of calls to allocate space in the nonpaged pool. The nonpaged pool is an area of system memory area for objects that cannot be written to disk, and must remain in physical memory as long as they are allocated (PoolNonpagedAllocs)",
        MetricType::Gauge,
        Some(idx::POOL_NONPAGED_ALLOCS),
    ),
    (
        "windows_memory_pool_nonpaged_bytes",
        "Number of bytes in the non-paged pool, an area of the system virtual memory that is used for objects that cannot be written to disk, but must remain in physical memory as long as they are allocated (PoolNonpagedBytes)",
        MetricType::Gauge,
        Some(idx::POOL_NONPAGED),
    ),
    (
        "windows_memory_pool_paged_allocs_total",
        "Number of calls to allocate space in the paged pool, regardless of the amount of space allocated in each call (PoolPagedAllocs)",
        MetricType::Counter,
        Some(idx::POOL_PAGED_ALLOCS),
    ),
    (
        "windows_memory_pool_paged_bytes",
        "(PoolPagedBytes)",
        MetricType::Gauge,
        Some(idx::POOL_PAGED),
    ),
    (
        "windows_memory_pool_paged_resident_bytes",
        "The size, in bytes, of the portion of the paged pool that is currently resident and active in physical memory. The paged pool is an area of the system virtual memory that is used for objects that can be written to disk when they are not being used (PoolPagedResidentBytes)",
        MetricType::Gauge,
        Some(idx::POOL_PAGED_RESIDENT),
    ),
    (
        "windows_memory_standby_cache_core_bytes",
        "The amount of physical memory, in bytes, that is assigned to the core standby cache page lists. This memory contains cached data and code that is not actively in use by processes, the system and the system cache (StandbyCacheCoreBytes)",
        MetricType::Gauge,
        Some(idx::STANDBY_CORE),
    ),
    (
        "windows_memory_standby_cache_lifetime_seconds",
        "The long-term average time, in seconds, that a page stays on the standby cache page lists before it is repurposed. Low values indicate memory pressure (LongTermAverageStandbyCacheLifetime)",
        MetricType::Gauge,
        Some(idx::STANDBY_LIFETIME),
    ),
    (
        "windows_memory_standby_cache_normal_priority_bytes",
        "The amount of physical memory, in bytes, that is assigned to the normal priority standby cache page lists. This memory contains cached data and code that is not actively in use by processes, the system and the system cache (StandbyCacheNormalPriorityBytes)",
        MetricType::Gauge,
        Some(idx::STANDBY_NORMAL),
    ),
    (
        "windows_memory_standby_cache_reserve_bytes",
        "The amount of physical memory, in bytes, that is assigned to the reserve standby cache page lists. This memory contains cached data and code that is not actively in use by processes, the system and the system cache (StandbyCacheReserveBytes)",
        MetricType::Gauge,
        Some(idx::STANDBY_RESERVE),
    ),
    (
        "windows_memory_system_cache_resident_bytes",
        "The size, in bytes, of the portion of the system file cache which is currently resident and active in physical memory (SystemCacheResidentBytes)",
        MetricType::Gauge,
        Some(idx::SYSTEM_CACHE_RESIDENT),
    ),
    (
        "windows_memory_system_code_resident_bytes",
        "The size, in bytes, of the pageable operating system code that is currently resident and active in physical memory (SystemCodeResidentBytes)",
        MetricType::Gauge,
        Some(idx::SYSTEM_CODE_RESIDENT),
    ),
    (
        "windows_memory_system_code_total_bytes",
        "The size, in bytes, of the pageable operating system code currently mapped into the system virtual address space (SystemCodeTotalBytes)",
        MetricType::Gauge,
        Some(idx::SYSTEM_CODE_TOTAL),
    ),
    (
        "windows_memory_system_driver_resident_bytes",
        "The size, in bytes, of the pageable physical memory being used by device drivers. It is the working set (physical memory area) of the drivers (SystemDriverResidentBytes)",
        MetricType::Gauge,
        Some(idx::SYSTEM_DRIVER_RESIDENT),
    ),
    (
        "windows_memory_system_driver_total_bytes",
        "The size, in bytes, of the pageable virtual memory currently being used by device drivers. Pageable memory can be written to disk when it is not being used (SystemDriverTotalBytes)",
        MetricType::Gauge,
        Some(idx::SYSTEM_DRIVER_TOTAL),
    ),
    (
        "windows_memory_transition_faults_total",
        "Number of faults rate at which page faults are resolved by recovering pages that were being used by another process sharing the page, or were on the modified page list or the standby list, or were being written to disk at the time of the page fault (TransitionFaultsPerSec)",
        MetricType::Counter,
        Some(idx::TRANSITION_FAULTS),
    ),
    (
        "windows_memory_transition_pages_repurposed_total",
        "Transition Pages RePurposed is the rate at which the number of transition cache pages were reused for a different purpose (TransitionPagesRePurposedPerSec)",
        MetricType::Counter,
        Some(idx::TRANSITION_REPURPOSED),
    ),
    (
        "windows_memory_write_copies_total",
        "The number of page faults caused by attempting to write that were satisfied by copying the page from elsewhere in physical memory (WriteCopiesPerSec)",
        MetricType::Counter,
        Some(idx::WRITE_COPIES),
    ),
    (
        "windows_memory_process_memory_limit_bytes",
        "The size of the user-mode portion of the virtual address space of the calling process, in bytes. This value depends on the type of process, the type of processor, and the configuration of the operating system.",
        MetricType::Gauge,
        None,
    ),
    (
        "windows_memory_physical_total_bytes",
        "The amount of actual physical memory, in bytes.",
        MetricType::Gauge,
        None,
    ),
    (
        "windows_memory_physical_free_bytes",
        "The amount of physical memory currently available, in bytes. This is the amount of physical memory that can be immediately reused without having to write its contents to disk first. It is the sum of the size of the standby, free, and zero lists.",
        MetricType::Gauge,
        None,
    ),
];

/// GlobalMemoryStatusEx 三项值的 emitted 顺序（Go collectGlobalMemoryStatus
/// 先于 PDH 输出）：process limit / physical total / physical free
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn global_values(status: Option<MemorySnapshot>) -> Vec<Option<f64>> {
    match status {
        None => vec![None, None, None],
        Some(status) => {
            vec![
                Some(status.total_virtual as f64),
                Some(status.total_phys as f64),
                Some(status.avail_phys as f64),
            ]
        }
    }
}

/// 由单实例样本 + GlobalMemoryStatusEx 构造全部 memory 指标族
/// （纯函数，Linux 宿主可测；GlobalMemoryStatusEx 缺失时对应 3 个族跳过）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_memory(
    sample: &[RawSample],
    status: Option<MemorySnapshot>,
) -> Vec<MetricFamily> {
    // GlobalMemoryStatusEx 值按 (名称, help, 类型, None) 表项顺序取用
    let mut globals = global_values(status);
    let mut out = Vec::with_capacity(FAMILIES.len());
    for (name, help, mtype, index) in FAMILIES {
        let mut family = MetricFamily::new(name, help, *mtype);
        match index {
            Some(index) => {
                if let Some(raw) = sample.get(*index) {
                    family.push(raw.value());
                }
            }
            None => {
                if let Some(Some(value)) = globals.first().copied() {
                    family.push(value);
                    globals.remove(0);
                }
            }
        }
        if !family.samples.is_empty() {
            out.push(family);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全零样本 + GlobalMemoryStatusEx 缺失：仅 32 个 PDH 族输出
    #[test]
    fn test_emit_memory_family_layout() {
        let sample: Vec<RawSample> = COUNTERS
            .iter()
            .map(|_| RawSample {
                first: 1024,
                second: 0,
                counter_type: 0,
            })
            .collect();
        let families = emit_memory(&sample, None);

        // GlobalMemoryStatusEx 缺失 → 3 个族无样本跳过
        assert_eq!(families.len(), 32);
        assert!(
            families
                .iter()
                .all(|family| !family.name.contains("process_memory")
                    && !family.name.contains("physical_"))
        );

        // PDH 计数器原值输出
        let available = families
            .iter()
            .find(|family| family.name == "windows_memory_available_bytes")
            .unwrap_or_else(|| panic!("缺少 available_bytes"));
        assert_eq!(available.mtype, MetricType::Gauge);
        assert_eq!(available.samples[0].value, 1024.0);

        // Counter 类型抽查（上游声明差异：pool allocs 两个方向不同）
        let nonpaged = families
            .iter()
            .find(|family| family.name == "windows_memory_pool_nonpaged_allocs_total")
            .unwrap_or_else(|| panic!("缺少 pool_nonpaged_allocs_total"));
        assert_eq!(nonpaged.mtype, MetricType::Gauge);
        let paged = families
            .iter()
            .find(|family| family.name == "windows_memory_pool_paged_allocs_total")
            .unwrap_or_else(|| panic!("缺少 pool_paged_allocs_total"));
        assert_eq!(paged.mtype, MetricType::Counter);
    }

    /// GlobalMemoryStatusEx 三项值进入对应指标
    #[test]
    fn test_emit_memory_global_status() {
        let sample: Vec<RawSample> = COUNTERS
            .iter()
            .map(|_| RawSample {
                first: 0,
                second: 0,
                counter_type: 0,
            })
            .collect();
        let status = MemorySnapshot {
            total_phys: 16_000_000_000,
            avail_phys: 4_000_000_000,
            total_virtual: 140_000_000_000_000,
        };
        let families = emit_memory(&sample, Some(status));

        let total = families
            .iter()
            .find(|family| family.name == "windows_memory_physical_total_bytes")
            .unwrap_or_else(|| panic!("缺少 physical_total_bytes"));
        assert_eq!(total.samples[0].value, 16_000_000_000.0);
        let free = families
            .iter()
            .find(|family| family.name == "windows_memory_physical_free_bytes")
            .unwrap_or_else(|| panic!("缺少 physical_free_bytes"));
        assert_eq!(free.samples[0].value, 4_000_000_000.0);
        let limit = families
            .iter()
            .find(|family| family.name == "windows_memory_process_memory_limit_bytes")
            .unwrap_or_else(|| panic!("缺少 process_memory_limit_bytes"));
        assert_eq!(limit.samples[0].value, 140_000_000_000_000.0);
    }

    /// 计数器清单与索引常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS.len(), 32);
        assert_eq!(COUNTERS[idx::AVAILABLE], "Available Bytes");
        assert_eq!(COUNTERS[idx::WRITE_COPIES], "Write Copies/sec");
        // 表内 Some 索引范围合法
        for (name, _, _, index) in FAMILIES {
            if let Some(index) = index {
                assert!(*index < COUNTERS.len(), "{name} 索引越界");
            }
        }
    }
}
