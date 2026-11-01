//! Windows SCM 服务模式（`foims-agent --service`）。
//!
//! 服务状态机：START_PENDING → RUNNING（接受 STOP）→ STOP_PENDING →
//! STOPPED。上报循环复用 [`foims_agent_core::reporter::Reporter`] 常驻
//! task；STOP 控制置位停止标志后 abort task（SCM 的停止指令即终止信号，
//! 无优雅收尾协议，断开中的 QUIC 连接由对端超时回收）。
//!
//! 服务经 install.cmd 以 `--service --config <路径> --cert-dir <目录>`
//! 方式安装（sc.exe create），安装/卸载脚本由发布 zip 随附。
//!
//! unsafe 约束：本模块的 Win32 调用与 `extern "system"` 回调声明不可避免
//! 涉及 unsafe，与 [`crate::ffi`] 同为平台层 FFI 模块（模块整体
//! `#[cfg(target_os = "windows")]`，Linux 宿主不编译）。

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use foims_agent_core::reporter::{Reporter, ReporterConfig};

use crate::WindowsPlatform;

/// Windows 服务名（与 install.cmd / uninstall.cmd 中 sc.exe 操作的名字一致）
pub const SERVICE_NAME: &str = "foims-agent";

/// 服务停止标志：SCM 控制 handler 置位，service_main 轮询后退出
static SERVICE_STOP: AtomicBool = AtomicBool::new(false);
/// 状态句柄：service_main 注册后存放，control handler 报告 STOP_PENDING 用。
/// SERVICE_STATUS_HANDLE 含裸指针不满足 Sync/Send，static 内以原始 usize
/// 存放（0 无意义：OnceLock 未初始化即未注册），读取处还原为句柄
static STATUS_HANDLE: OnceLock<usize> = OnceLock::new();
/// 服务启动参数：run_as_service 在 dispatcher 前装入，service_main 读取
static SERVICE_BOOT: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

/// 以 Windows 服务身份运行上报循环（阻塞至服务停止）。
///
/// 供 main 的 `--service` 分支调用；配置/证书目录与 console 模式同语义。
/// 直接在控制台运行 `--service` 时 dispatcher 返回错误 1063（进程不是
/// 服务控制器启动），此处原样记录并返回失败退出码。
pub fn run_as_service(config_path: &Path, cert_dir: &Path) -> std::process::ExitCode {
    if SERVICE_BOOT
        .set((config_path.to_path_buf(), cert_dir.to_path_buf()))
        .is_err()
    {
        tracing::error!("服务启动参数重复装入（进程内仅允许一次 --service）");
        return std::process::ExitCode::FAILURE;
    }
    // 服务名跨 dispatcher 生命周期持有（SCM 在 StartServiceCtrlDispatcherW
    // 阻塞期间持续读取该指针，栈值随函数返回失效会悬垂）
    let name: &'static HSTRING = Box::leak(Box::new(HSTRING::from(SERVICE_NAME)));
    // lpServiceName 声明为 PWSTR（可写），SCM 实际只读；常量串按位宽转 mut
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_ptr() as *mut u16),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "服务调度器退出（1063 表示未由服务控制器启动，请用 install.cmd 安装后由 SCM 拉起）");
            std::process::ExitCode::FAILURE
        }
    }
}

/// 上报状态到 SCM（等价 SetServiceStatus 的薄封装）
fn report_state(
    handle: SERVICE_STATUS_HANDLE,
    state: SERVICE_STATUS_CURRENT_STATE,
    checkpoint: u32,
    wait_hint_ms: u32,
) {
    let accepts = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint_ms,
    };
    if let Err(error) = unsafe { SetServiceStatus(handle, &status) } {
        tracing::warn!(%error, "上报服务状态失败");
    }
}

/// SCM 控制处理回调：接受 STOP，其余控制码一律不实现
unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP {
        SERVICE_STOP.store(true, Ordering::SeqCst);
        if let Some(&handle) = STATUS_HANDLE.get() {
            report_state(
                SERVICE_STATUS_HANDLE(handle as *mut c_void),
                SERVICE_STOP_PENDING,
                1,
                5_000,
            );
        }
        0 // NO_ERROR
    } else {
        1 // ERROR_CALL_NOT_IMPLEMENTED
    }
}

/// 服务入口（SCM 在独立线程调用）：注册控制回调 → 起上报循环 →
/// 轮询停止标志 → 中断任务 → 报告 STOPPED
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name: &'static HSTRING = Box::leak(Box::new(HSTRING::from(SERVICE_NAME)));
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(control_handler), None)
    } {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "注册服务控制处理器失败");
            return;
        }
    };
    let _ = STATUS_HANDLE.set(handle.0 as usize);
    report_state(handle, SERVICE_START_PENDING, 0, 3_000);

    // 启动参数由 run_as_service 装入；--service 直接由 SCM 拉起时必已就位
    let Some((config_path, cert_dir)) = SERVICE_BOOT.get() else {
        tracing::error!("服务启动参数缺失（进程未以 --service 正常引导）");
        report_state(handle, SERVICE_STOPPED, 0, 0);
        return;
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "构建 tokio 运行时失败");
            report_state(handle, SERVICE_STOPPED, 0, 0);
            return;
        }
    };

    report_state(handle, SERVICE_RUNNING, 0, 0);
    tracing::info!("FOIMS Agent 服务已启动（SCM 模式）");

    // 上报循环放入 task：Reporter::run 无停止协议，STOP 时 abort 中断
    let config_path = config_path.clone();
    let cert_dir = cert_dir.clone();
    let reporter_task = runtime.spawn(async move {
        match ReporterConfig::load(&config_path, cert_dir) {
            Ok(config) => {
                let mut reporter = Reporter::new(config, WindowsPlatform::new());
                reporter.run().await;
            }
            Err(error) => {
                tracing::error!(%error, "加载配置失败，服务空转（配置由服务端配置包提供，请核对安装目录）");
                // 空转等待停止指令，避免反复重启（服务错误由日志暴露）
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        }
    });

    while !SERVICE_STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));
    }
    tracing::info!("收到服务停止指令，正在退出上报循环");
    reporter_task.abort();
    // abort 后给运行时留出回收窗口，避免遗留阻塞 IO 拖住进程退出
    runtime.shutdown_timeout(Duration::from_secs(3));
    report_state(handle, SERVICE_STOPPED, 0, 0);
    tracing::info!("FOIMS Agent 服务已停止");
}
