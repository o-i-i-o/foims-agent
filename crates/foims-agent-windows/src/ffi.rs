//! Win32 FFI 安全封装：PDH 性能计数器、注册表、SCM、系统信息、卷信息。
//!
//! 本模块是整个 crate 唯一允许 `unsafe` 的位置（workspace lints 为 deny，
//! 仅此模块局部 allow）。所有 FFI 调用用 `cfg(target_os = "windows")`
//! 门控，Linux 宿主编译时本模块为空壳（仅错误类型），纯解析/计算逻辑
//! 一律拆到调用方或独立函数以便单测。
//!
//! 封装范围（对齐 Go 源 internal/pdh、internal/headers 与
//! golang.org/x/sys/windows 的调用面）：
//! - PDH：`PdhOpenQueryW` / `PdhAddEnglishCounterW`（支持 `(*)` 通配实例，
//!   与 windows_exporter 一致）/ `PdhCollectQueryData` / `PdhGetRawCounterValue`
//!   / `PdhGetRawCounterArrayW` / `PdhGetCounterInfoW`（取计数器类型）/
//!   `PdhCloseQuery`（Drop 关闭）；
//! - 注册表：`RegGetValueW`（SZ/DWORD），os 采集器与 MachineGuid 使用；
//! - 系统信息：`GetTickCount64` / `GlobalMemoryStatusEx` / `GetComputerNameExW`；
//! - SCM：`OpenSCManagerW` / `EnumServicesStatusExW` / `OpenServiceW` /
//!   `QueryServiceConfigW` / `CloseServiceHandle`（Drop 关闭）；
//! - 进程时间：`OpenProcess` + `GetProcessTimes`（service 采集器进程启动时刻）；
//! - 卷信息：`GetDiskFreeSpaceExW` / `GetVolumeInformationW` / `GetDriveTypeW`
//!   （logical_disk 采集器容量与 info 标签）。
//!
//! 读取一律走 raw 值（FirstValue/SecondValue），换算语义与
//! windows_exporter 的 CounterTypeRaw 一致（见 collectors/mod.rs 的
//! [`crate::collectors::raw_to_value`]）。

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::c_void;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS, GetLastError,
};
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW,
};
use windows::Win32::System::Performance::{
    PDH_COUNTER_INFO_W, PDH_HCOUNTER, PDH_HQUERY, PDH_RAW_COUNTER, PDH_RAW_COUNTER_ITEM_W,
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetCounterInfoW,
    PdhGetRawCounterArrayW, PdhGetRawCounterValue, PdhOpenQueryW,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::Win32::System::SystemInformation::{
    COMPUTER_NAME_FORMAT, ComputerNameDnsDomain, ComputerNameDnsFullyQualified,
    ComputerNameDnsHostname, GetComputerNameExW, GetTickCount64, GlobalMemoryStatusEx,
    MEMORYSTATUSEX,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::{PCWSTR, PWSTR};

/// FFI 错误：携带 Win32/PDH 状态码与调用点说明
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    /// PDH 返回的非零状态码
    #[error("PDH 调用失败 {call}: 0x{code:08X}")]
    Pdh { call: &'static str, code: u32 },
    /// Win32 调用失败（GetLastError）
    #[error("Win32 调用失败 {call}: {code}")]
    Win32 { call: &'static str, code: u32 },
    /// 返回字符串含内嵌 NUL 等无法解释为 UTF-16 的情形
    #[error("FFI 字符串转换失败 {call}")]
    String { call: &'static str },
}

/// windows crate 的 Result 错误 → FfiError::Win32（HRESULT 低 16 位即 Win32 错误码）
fn win32_error(call: &'static str, error: &windows::core::Error) -> FfiError {
    FfiError::Win32 {
        call,
        code: (error.code().0 as u32) & 0xFFFF,
    }
}

/// Rust 字符串 → 以 NUL 结尾的 UTF-16
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 读取 NUL 结尾 UTF-16 字符串（PWSTR → String）
///
/// # Safety
/// `ptr` 必须指向以 NUL 结尾的合法 UTF-16 缓冲区（或为空指针）
unsafe fn pwstr_to_string(ptr: PWSTR, call: &'static str) -> Result<String, FfiError> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    let mut len = 0usize;
    // SAFETY: 调用方保证 ptr 指向 NUL 结尾的 UTF-16 缓冲区
    unsafe {
        while *ptr.as_ptr().add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
    String::from_utf16(slice).map_err(|_| FfiError::String { call })
}

// PDH

/// PDH 查询：RAII 持有 HQUERY，Drop 时关闭
pub struct PdhQuery {
    handle: PDH_HQUERY,
}

// PDH 句柄无线程亲和性：PDH 文档允许跨线程使用/关闭查询与计数器
// （windows crate 的裸指针 newtype 默认不实现 Send/Sync，此处安全豁免）
unsafe impl Send for PdhQuery {}
unsafe impl Sync for PdhQuery {}

/// PDH 计数器句柄（生命周期依附于所属 [`PdhQuery`]）
#[derive(Debug, Clone, Copy)]
pub struct PdhCounter {
    handle: PDH_HCOUNTER,
}

unsafe impl Send for PdhCounter {}
unsafe impl Sync for PdhCounter {}

impl PdhQuery {
    /// 打开 PDH 查询
    pub fn open() -> Result<Self, FfiError> {
        let mut handle = PDH_HQUERY::default();
        // SAFETY: 输出指针指向局部变量，句柄由本结构独占管理
        let status = unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut handle) };
        if status != ERROR_SUCCESS.0 {
            return Err(FfiError::Pdh {
                call: "PdhOpenQueryW",
                code: status,
            });
        }
        Ok(Self { handle })
    }

    /// 添加英文计数器（路径可含 `(*)` 通配实例，与 windows_exporter 一致）
    pub fn add_english_counter(&mut self, path: &str) -> Result<PdhCounter, FfiError> {
        let path_w = wide(path);
        let mut handle = PDH_HCOUNTER::default();
        // SAFETY: path_w 为 NUL 结尾缓冲区，输出指针指向局部变量
        let status =
            unsafe { PdhAddEnglishCounterW(self.handle, PCWSTR(path_w.as_ptr()), 0, &mut handle) };
        if status != ERROR_SUCCESS.0 {
            return Err(FfiError::Pdh {
                call: "PdhAddEnglishCounterW",
                code: status,
            });
        }
        Ok(PdhCounter { handle })
    }

    /// 采样一次（同类计数器需先采样才能读到有效 raw 值）
    pub fn collect(&self) -> Result<(), FfiError> {
        // SAFETY: 句柄由本结构持有，合法
        let status = unsafe { PdhCollectQueryData(self.handle) };
        if status != ERROR_SUCCESS.0 {
            return Err(FfiError::Pdh {
                call: "PdhCollectQueryData",
                code: status,
            });
        }
        Ok(())
    }
}

impl Drop for PdhQuery {
    fn drop(&mut self) {
        // SAFETY: 句柄由本结构持有且仅关闭一次
        unsafe { PdhCloseQuery(self.handle) };
    }
}

impl PdhCounter {
    /// 计数器类型（perflib 类型常量，见 collectors::raw_to_value）
    pub fn counter_type(&self) -> Result<u32, FfiError> {
        // 先探缓冲区大小，再取完整信息（dwType 位于固定布局头部）
        let mut size = 0u32;
        // SAFETY: 首次调用传空指针仅探测所需大小，PDH 返回 MORE_DATA
        let _ = unsafe { PdhGetCounterInfoW(self.handle, false, &mut size, None) };
        if size == 0 {
            return Err(FfiError::Pdh {
                call: "PdhGetCounterInfoW",
                code: 0,
            });
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: 缓冲区大小与 PDH 要求一致，PDH_COUNTER_INFO_W 按 8 字节对齐
        let status = unsafe {
            PdhGetCounterInfoW(
                self.handle,
                false,
                &mut size,
                Some(buffer.as_mut_ptr().cast::<PDH_COUNTER_INFO_W>()),
            )
        };
        if status != ERROR_SUCCESS.0 {
            return Err(FfiError::Pdh {
                call: "PdhGetCounterInfoW",
                code: status,
            });
        }
        // SAFETY: dwType 位于结构体头部（非联合体字段），按声明布局读取
        let info = unsafe { &*buffer.as_ptr().cast::<PDH_COUNTER_INFO_W>() };
        Ok(info.dwType)
    }

    /// 单实例计数器原始值（FirstValue, SecondValue, CStatus）
    pub fn raw_single(&self) -> Result<(i64, i64, u32), FfiError> {
        let mut value = PDH_RAW_COUNTER::default();
        // SAFETY: 输出指针指向局部变量
        let status = unsafe { PdhGetRawCounterValue(self.handle, None, &mut value) };
        if status != ERROR_SUCCESS.0 {
            return Err(FfiError::Pdh {
                call: "PdhGetRawCounterValue",
                code: status,
            });
        }
        Ok((value.FirstValue, value.SecondValue, value.CStatus))
    }

    /// 通配计数器的原始值数组：[(实例名, FirstValue, SecondValue, CStatus)]
    pub fn raw_array(&self) -> Result<Vec<(String, i64, i64, u32)>, FfiError> {
        let mut size = 0u32;
        let mut count = 0u32;
        // SAFETY: 首次调用传空指针仅探测所需大小，PDH 返回 PDH_MORE_DATA
        let _ = unsafe { PdhGetRawCounterArrayW(self.handle, &mut size, &mut count, None) };
        if size == 0 {
            return Err(FfiError::Pdh {
                call: "PdhGetRawCounterArrayW",
                code: 0,
            });
        }
        // 缓冲区声明在循环外：break 后仍需按 PDH 写入的布局解析
        //（循环内先赋值后使用，break 路径必然已初始化）
        let mut buffer: Vec<u8>;
        loop {
            buffer = vec![0u8; size as usize + 8];
            let mut needed = size;
            // SAFETY: 缓冲区已按 PDH 要求分配（含少量余量，兼容 Server 2012 R2
            // 越界写终结符的行为，与 windows_exporter 的 pdhBufferSlack 一致）
            let status = unsafe {
                PdhGetRawCounterArrayW(
                    self.handle,
                    &mut needed,
                    &mut count,
                    Some(buffer.as_mut_ptr().cast::<PDH_RAW_COUNTER_ITEM_W>()),
                )
            };
            if status == ERROR_SUCCESS.0 {
                break;
            }
            if status != ERROR_MORE_DATA.0 || needed <= size {
                return Err(FfiError::Pdh {
                    call: "PdhGetRawCounterArrayW",
                    code: status,
                });
            }
            size = needed;
        }
        // SAFETY: PDH 已在缓冲区内写入 count 个连续元素
        let items = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<PDH_RAW_COUNTER_ITEM_W>(),
                count as usize,
            )
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            // SAFETY: szName 由 PDH 填充，指向缓冲区内 NUL 结尾 UTF-16
            let name = unsafe { pwstr_to_string(item.szName, "PdhGetRawCounterArrayW") }?;
            out.push((
                name,
                item.RawValue.FirstValue,
                item.RawValue.SecondValue,
                item.RawValue.CStatus,
            ));
        }
        Ok(out)
    }
}

// 注册表

/// 读取注册表 REG_SZ 字符串值
pub fn reg_read_string(root: HKEY, subkey: &str, value: &str) -> Result<String, FfiError> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    // 预留缓冲区；若不足（ERROR_MORE_DATA）再按所需大小重试一次
    let mut buffer = vec![0u8; 512];
    loop {
        let mut size = buffer.len() as u32;
        // SAFETY: 各指针均指向本函数持有的局部缓冲区
        let status = unsafe {
            RegGetValueW(
                root,
                PCWSTR(subkey_w.as_ptr()),
                PCWSTR(value_w.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                Some(&mut size),
            )
        };
        // WIN32_ERROR 为结构体 newtype，不能作 match 模式，改用 if/else 比较
        if status == ERROR_SUCCESS {
            // as_chunks 按 2 字节组切分（剩余不足一组的尾部不参与解码）
            let chars: Vec<u16> = buffer[..size as usize]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .take_while(|unit| *unit != 0)
                .collect();
            return String::from_utf16(&chars).map_err(|_| FfiError::String {
                call: "RegGetValueW",
            });
        } else if status == ERROR_MORE_DATA {
            buffer = vec![0u8; (size as usize).max(buffer.len() * 2)];
            continue;
        } else {
            return Err(FfiError::Win32 {
                call: "RegGetValueW",
                code: status.0,
            });
        }
    }
}

/// 读取注册表 REG_DWORD 值
pub fn reg_read_u32(root: HKEY, subkey: &str, value: &str) -> Result<u32, FfiError> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let mut data: u32 = 0;
    let mut size = 4u32;
    // SAFETY: 输出指针与长度匹配 u32 数据
    let status = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(data).cast::<c_void>()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(FfiError::Win32 {
            call: "RegGetValueW",
            code: status.0,
        });
    }
    Ok(data)
}

/// 注册表根键：HKEY_LOCAL_MACHINE
pub const REGISTRY_LOCAL_MACHINE: HKEY = HKEY_LOCAL_MACHINE;

// 系统信息

/// GetTickCount64：系统启动至今毫秒数
pub fn tick_count_millis() -> u64 {
    // SAFETY: 无参数系统调用
    unsafe { GetTickCount64() }
}

/// GlobalMemoryStatusEx 结果
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryStatus {
    /// 物理内存总量（字节）
    pub total_phys: u64,
    /// 可用物理内存（字节）
    pub avail_phys: u64,
    /// 用户态虚拟地址空间总量（字节）
    pub total_virtual: u64,
}

/// 读取全局内存状态
pub fn global_memory_status() -> Result<MemoryStatus, FfiError> {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: 结构体已按 API 要求初始化 dwLength
    // windows 0.62 的 Free 函数返回 Result，失败即非零 BOOL
    unsafe { GlobalMemoryStatusEx(&mut status) }
        .map_err(|error| win32_error("GlobalMemoryStatusEx", &error))?;
    Ok(MemoryStatus {
        total_phys: status.ullTotalPhys,
        avail_phys: status.ullAvailPhys,
        total_virtual: status.ullTotalVirtual,
    })
}

/// 计算机名格式（对齐 sysinfoapi.GetComputerName 的三种 DNS 形式）
#[derive(Debug, Clone, Copy)]
pub enum ComputerNameKind {
    /// DNS 主机名
    Hostname,
    /// DNS 域名
    Domain,
    /// 完整限定域名
    FullyQualified,
}

impl ComputerNameKind {
    fn to_format(self) -> COMPUTER_NAME_FORMAT {
        match self {
            ComputerNameKind::Hostname => ComputerNameDnsHostname,
            ComputerNameKind::Domain => ComputerNameDnsDomain,
            ComputerNameKind::FullyQualified => ComputerNameDnsFullyQualified,
        }
    }
}

/// 读取计算机名（os 采集器 hostname 指标）
pub fn computer_name(kind: ComputerNameKind) -> Result<String, FfiError> {
    let mut size = 0u32;
    // SAFETY: 首次调用传空指针探测所需字符数（探测失败即 MORE_DATA，忽略错误仅看 size）
    let _ = unsafe { GetComputerNameExW(kind.to_format(), None, &mut size) };
    if size == 0 {
        return Err(FfiError::Win32 {
            call: "GetComputerNameExW",
            code: 0,
        });
    }
    let mut buffer = vec![0u16; size as usize];
    // SAFETY: 缓冲区容量与探测值一致（PWSTR 指向可写缓冲区）
    unsafe {
        GetComputerNameExW(
            kind.to_format(),
            Some(PWSTR(buffer.as_mut_ptr())),
            &mut size,
        )
    }
    .map_err(|error| win32_error("GetComputerNameExW", &error))?;
    buffer.truncate(size as usize);
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    String::from_utf16(&buffer).map_err(|_| FfiError::String {
        call: "GetComputerNameExW",
    })
}

// 卷信息（logical_disk 采集器）

/// 卷容量（字节）
#[derive(Debug, Clone, Copy)]
pub struct VolumeSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// GetDiskFreeSpaceExW：卷空闲/总容量
pub fn volume_space(root: &str) -> Result<VolumeSpace, FfiError> {
    let root_w = wide(root);
    let mut free = 0u64;
    let mut total = 0u64;
    let mut _remaining = 0u64;
    // SAFETY: 各输出指针均指向局部变量
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root_w.as_ptr()),
            Some(&mut free),
            Some(&mut total),
            Some(&mut _remaining),
        )
    }
    .map_err(|error| win32_error("GetDiskFreeSpaceExW", &error))?;
    Ok(VolumeSpace {
        free_bytes: free,
        total_bytes: total,
    })
}

/// GetVolumeInformationW 结果
#[derive(Debug, Clone, Default)]
pub struct VolumeInfo {
    /// 卷标
    pub label: String,
    /// 文件系统名（NTFS/FAT32…）
    pub filesystem: String,
    /// 卷序列号（大写十六进制）
    pub serial_number: String,
    /// 卷是否只读（FILE_READ_ONLY_VOLUME）
    pub readonly: bool,
}

/// GetVolumeInformationW：卷标/文件系统/序列号/只读标志
pub fn volume_information(root: &str) -> Result<VolumeInfo, FfiError> {
    let root_w = wide(root);
    let mut label = vec![0u16; 261];
    let mut filesystem = vec![0u16; 261];
    let mut serial = 0u32;
    let mut flags = 0u32;
    let mut _max_component = 0u32;
    // SAFETY: 各缓冲区容量以 slice 长度传入（字符数）
    unsafe {
        GetVolumeInformationW(
            PCWSTR(root_w.as_ptr()),
            Some(&mut label),
            Some(&mut serial),
            Some(&mut _max_component),
            Some(&mut flags),
            Some(&mut filesystem),
        )
    }
    .map_err(|error| win32_error("GetVolumeInformationW", &error))?;
    Ok(VolumeInfo {
        label: utf16_until_nul(&label),
        filesystem: utf16_until_nul(&filesystem),
        serial_number: format!("{serial:X}"),
        readonly: flags & 0x0000_0001 != 0, // FILE_READ_ONLY_VOLUME
    })
}

/// 截断 NUL 之后的 UTF-16 片段并转为 String
fn utf16_until_nul(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..end]).unwrap_or_default()
}

/// GetDriveTypeW：卷类型（DRIVE_* 常量）
pub fn drive_type(root: &str) -> u32 {
    let root_w = wide(root);
    // SAFETY: 传入 NUL 结尾路径
    unsafe { GetDriveTypeW(PCWSTR(root_w.as_ptr())) }
}

// SCM（service 采集器）

/// 服务管理器连接：RAII 持有 SCM 句柄
pub struct Scm {
    handle: windows::Win32::System::Services::SC_HANDLE,
}

// SCM 句柄无线程亲和性：SCM API 允许跨线程使用服务句柄
// （windows crate 的裸指针 newtype 默认不实现 Send/Sync，此处安全豁免）
unsafe impl Send for Scm {}
unsafe impl Sync for Scm {}

/// EnumServicesStatusExW 返回的单服务快照
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub name: String,
    /// SERVICE_STATUS_PROCESS.dwCurrentState（1-7，语义见 service 采集器）
    pub state: u32,
    /// SERVICE_STATUS_PROCESS.dwProcessId
    pub pid: u32,
}

/// QueryServiceConfigW 结果
#[derive(Debug, Clone, Default)]
pub struct ServiceConfig {
    pub display_name: String,
    pub run_as: String,
    pub path_name: String,
    /// QUERY_SERVICE_CONFIG.dwStartType（0-4，语义见 service 采集器）
    pub start_type: u32,
}

impl Scm {
    /// 打开服务管理器（仅枚举权限）
    pub fn open() -> Result<Self, FfiError> {
        // SAFETY: 两个名称参数均传 null（本机、SERVICES_ACTIVE_DATABASE 默认）
        let handle =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }
                .map_err(|error| win32_error("OpenSCManagerW", &error))?;
        Ok(Self { handle })
    }

    /// 枚举全部 Win32 服务（SERVICE_WIN32，含已停止；对齐 Go 的 queryAllServices）
    pub fn services(&self) -> Result<Vec<ServiceEntry>, FfiError> {
        // 初始缓冲区对齐 Go 的 200KB 起始值
        let mut buffer = vec![0u8; 200 * 1024];
        loop {
            let mut bytes_needed = 0u32;
            let mut returned = 0u32;
            // SAFETY: 缓冲区与大小匹配；EnumServicesStatusExW 以
            // ENUM_SERVICE_STATUS_PROCESS 数组 + 字符串区填充缓冲区
            let result = unsafe {
                EnumServicesStatusExW(
                    self.handle,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(buffer.as_mut_slice()),
                    &mut bytes_needed,
                    &mut returned,
                    None,
                    PCWSTR::null(),
                )
            };
            let Err(error) = result else {
                return Self::parse_services(&buffer, returned);
            };
            let code = match win32_error("EnumServicesStatusExW", &error) {
                FfiError::Win32 { code, .. } => code,
                other => return Err(other),
            };
            if code != ERROR_MORE_DATA.0 {
                return Err(FfiError::Win32 {
                    call: "EnumServicesStatusExW",
                    code,
                });
            }
            // 注意：bytes_needed 是“相对当前缓冲区”的追加量（见 Go 注释）
            buffer = vec![0u8; buffer.len() + bytes_needed as usize];
        }
    }

    /// 解析缓冲区中的 ENUM_SERVICE_STATUS_PROCESS 数组
    ///
    /// # Safety
    /// 缓冲区必须由 EnumServicesStatusExW 刚刚成功填充
    fn parse_services(buffer: &[u8], returned: u32) -> Result<Vec<ServiceEntry>, FfiError> {
        // SAFETY: 对齐与有效性由 EnumServicesStatusExW 成功返回保证
        let items = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                returned as usize,
            )
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            // SAFETY: lpServiceName 指向缓冲区内 NUL 结尾 UTF-16
            let name = unsafe { pwstr_to_string(item.lpServiceName, "EnumServicesStatusExW") }?;
            out.push(ServiceEntry {
                name,
                state: item.ServiceStatusProcess.dwCurrentState.0,
                pid: item.ServiceStatusProcess.dwProcessId,
            });
        }
        Ok(out)
    }

    /// 查询单服务配置（服务不可读配置时返回 Ok(None)，对齐 Go 的 configAvailable）
    pub fn service_config(&self, name: &str) -> Result<Option<ServiceConfig>, FfiError> {
        let name_w = wide(name);
        // SAFETY: name_w 为 NUL 结尾缓冲区
        let service = unsafe { OpenServiceW(self.handle, PCWSTR(name_w.as_ptr()), 0x0001) };
        // SERVICE_QUERY_CONFIG = 0x0001
        let service = match service {
            Ok(handle) if !handle.is_invalid() => handle,
            Ok(_) => return Ok(None),
            Err(_) => {
                let code = unsafe { GetLastError() }.0;
                // 服务已消失等访问错误：按无配置处理并记录状态码
                tracing::debug!(service = name, code, "OpenServiceW 失败，按无配置处理");
                return Ok(None);
            }
        };
        let result = Self::query_config(service, name);
        // SAFETY: 句柄由 OpenServiceW 创建，仅关闭一次；关闭失败无法补救，忽略
        let _ = unsafe { CloseServiceHandle(service) };
        result
    }

    /// QueryServiceConfigW 循环扩容读取
    fn query_config(
        service: windows::Win32::System::Services::SC_HANDLE,
        name: &str,
    ) -> Result<Option<ServiceConfig>, FfiError> {
        let mut size = 1024u32;
        loop {
            let mut buffer = vec![0u8; size as usize];
            let mut needed = size;
            // SAFETY: 缓冲区按 QUERY_SERVICE_CONFIGW + 字符串区布局由 API 填充
            let result = unsafe {
                QueryServiceConfigW(
                    service,
                    Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                    size,
                    &mut needed,
                )
            };
            if result.is_ok() {
                // SAFETY: QueryServiceConfigW 成功后头部为有效 QUERY_SERVICE_CONFIGW
                let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
                // SAFETY: 各 PWSTR 均指向缓冲区内 NUL 结尾 UTF-16
                let (display_name, run_as, path_name) = unsafe {
                    (
                        pwstr_to_string(config.lpDisplayName, "QueryServiceConfigW")?,
                        pwstr_to_string(config.lpServiceStartName, "QueryServiceConfigW")?,
                        pwstr_to_string(config.lpBinaryPathName, "QueryServiceConfigW")?,
                    )
                };
                return Ok(Some(ServiceConfig {
                    display_name,
                    run_as,
                    path_name,
                    start_type: config.dwStartType.0,
                }));
            }
            // windows 0.62 将 BOOL 型 API 包装为 Result：Err 即调用失败
            let Err(error) = result else {
                // Ok 分支已在上方 return，理论不可达；防御性兜底（禁止 unreachable!）
                return Err(FfiError::Win32 {
                    call: "QueryServiceConfigW",
                    code: 0,
                });
            };
            let code = match win32_error("QueryServiceConfigW", &error) {
                FfiError::Win32 { code, .. } => code,
                other => return Err(other),
            };
            if code == ERROR_INSUFFICIENT_BUFFER.0 || code == ERROR_MORE_DATA.0 {
                // ERROR_INSUFFICIENT_BUFFER(0x7A) / ERROR_MORE_DATA(0xEA)
                if needed <= size {
                    return Err(FfiError::Win32 {
                        call: "QueryServiceConfigW",
                        code,
                    });
                }
                size = needed;
                continue;
            }
            tracing::debug!(
                service = name,
                code,
                "QueryServiceConfigW 失败，按无配置处理"
            );
            return Ok(None);
        }
    }
}

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: 句柄由本结构持有且仅关闭一次；关闭失败无法补救，忽略
        let _ = unsafe { CloseServiceHandle(self.handle) };
    }
}

/// 服务进程创建时刻（Unix 整秒；对齐 Go 的 Filetime.Nanoseconds()/1e9 整除语义）；
/// 进程不可打开/已退出时返回 None
pub fn process_create_time_unix(pid: u32) -> Option<f64> {
    // SAFETY: 权限为 PROCESS_QUERY_LIMITED_INFORMATION，仅查询
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let process = match process {
        Ok(handle) if !handle.is_invalid() => handle,
        _ => return None,
    };
    let mut creation = windows::Win32::Foundation::FILETIME::default();
    let mut exit = windows::Win32::Foundation::FILETIME::default();
    let mut kernel = windows::Win32::Foundation::FILETIME::default();
    let mut user = windows::Win32::Foundation::FILETIME::default();
    // SAFETY: 各 FILETIME 指针均指向局部变量
    // windows 0.62 将 BOOL 型 API 包装为 Result：Err 即调用失败
    let times =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: 句柄仅关闭一次；关闭失败无法补救，忽略
    let _ = unsafe { CloseHandle(process) };
    if times.is_err() {
        return None;
    }
    // FILETIME = 100ns since 1601-01-01；整除 1e7 得 Unix 整秒（对齐 Go processStartTime/1e9）
    let ticks = (creation.dwHighDateTime as u64) << 32 | creation.dwLowDateTime as u64;
    Some(((ticks - 116_444_736_000_000_000) / 10_000_000) as f64)
}

// 机器标识

/// 读取注册表 MachineGuid（HKLM\SOFTWARE\Microsoft\Cryptography）
pub fn machine_guid() -> Result<String, FfiError> {
    reg_read_string(
        REGISTRY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
    )
}
