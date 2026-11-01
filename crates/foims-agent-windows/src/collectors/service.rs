//! service 采集器（对齐 Go `internal/collector/service/`）。
//!
//! 枚举 SCM 全部 Win32 服务（SERVICE_WIN32 + SERVICE_STATE_ALL），输出
//! 4 个指标族；state 的 7 项 0/1 序列与 start_mode 的 5 项 0/1 序列取值
//! 与 Go 的 apiStateValues / apiStartModeValues 一致（Go 遍历 map 顺序
//! 不定，此处按 windows.h 常量声明序固定输出）。
//!
//! ## 与 Go 的已知偏离
//! - include/exclude 正则与 start-mode-include 过滤未移植；
//! - 服务配置查询为串行（Go 用 4 worker 并发 + 配置变更缓存 + 指标缓存）；
//! - 配置读取失败统一按「无配置」处理（Go 仅 ERROR_FILE_NOT_FOUND 类
//!   错误降级为无配置，其余错误整服务跳过；FFI 封装未区分错误类别）；
//! - 进程创建时刻经 OpenProcess+GetProcessTimes 读取，失败/已退出按缺失
//!   处理（Go 同语义，仅日志级别区分）。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 服务状态码 → 文本（对齐 Go apiStateValues，键即 winsvc.h SERVICE_* 常量）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const STATE_VALUES: &[(u32, &str)] = &[
    (5, "continue pending"),
    (6, "pause pending"),
    (7, "paused"),
    (4, "running"),
    (2, "start pending"),
    (3, "stop pending"),
    (1, "stopped"),
];

/// 启动类型码 → 文本（对齐 Go apiStartModeValues，键即 winsvc.h
/// SERVICE_*_START 常量）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const START_MODE_VALUES: &[(u32, &str)] = &[
    (2, "auto"),
    (0, "boot"),
    (4, "disabled"),
    (3, "manual"),
    (1, "system"),
];

/// 启动类型码 → 文本（未知类型返回 None，调用方按 Go 语义告警并跳过服务）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn start_mode_name(code: u32) -> Option<&'static str> {
    START_MODE_VALUES
        .iter()
        .find(|(candidate, _)| *candidate == code)
        .map(|(_, name)| *name)
}

/// 服务配置快照（跨平台纯数据；配置不可读时整体为 None）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct ServiceSnapshot {
    pub display_name: String,
    pub run_as: String,
    pub path_name: String,
    /// 启动类型文本（未知类型的服务在采集阶段已跳过，这里恒为 Some）
    pub start_mode: Option<String>,
}

/// 单服务枚举输入（跨平台纯数据，windows 分支从 ffi 类型映射）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct ServiceInput {
    pub name: String,
    /// SERVICE_STATUS_PROCESS.dwCurrentState（1-7）
    pub state: u32,
    /// SERVICE_STATUS_PROCESS.dwProcessId（0 表示未运行）
    pub pid: u32,
    /// 进程创建时刻（Unix 整秒；未知为 None，跳过 process 指标）
    pub start_time: Option<f64>,
    /// 服务配置（不可读为 None：info 标签取空串且无 start_mode 指标）
    pub config: Option<ServiceSnapshot>,
}

/// 由服务输入构造全部 service 指标族（纯函数，Linux 宿主可测）。
///
/// 族序镜像 Go serviceMetrics 的发射顺序：info → start_mode → state →
/// process（start_mode 仅配置可读的服务输出，process 仅 pid 非 0 且
/// 创建时刻已知的服务输出）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_service(inputs: &[ServiceInput]) -> Vec<MetricFamily> {
    let mut out = Vec::with_capacity(4);

    // info：标签 name/display_name/run_as/path_name，配置缺失取空串
    // （对齐 Go 的 mgr.Config 零值）
    let mut info = MetricFamily::new(
        "windows_service_info",
        "A metric with a constant '1' value labeled with service information",
        MetricType::Gauge,
    );
    for input in inputs {
        let (display_name, run_as, path_name) = match &input.config {
            Some(config) => (
                config.display_name.as_str(),
                config.run_as.as_str(),
                config.path_name.as_str(),
            ),
            None => ("", "", ""),
        };
        info.push_labeled(
            vec![
                ("name".to_string(), input.name.clone()),
                ("display_name".to_string(), display_name.to_string()),
                ("run_as".to_string(), run_as.to_string()),
                ("path_name".to_string(), path_name.to_string()),
            ],
            1.0,
        );
    }
    if !info.samples.is_empty() {
        out.push(info);
    }

    // start_mode：每个配置可读的服务 5 项 0/1（startMode 为空时 Go 不发射）
    let mut start_mode = MetricFamily::new(
        "windows_service_start_mode",
        "The start mode of the service (StartMode)",
        MetricType::Gauge,
    );
    for input in inputs {
        let Some(current) = input
            .config
            .as_ref()
            .and_then(|config| config.start_mode.as_deref())
        else {
            continue;
        };
        for (_, mode) in START_MODE_VALUES {
            start_mode.push_labeled(
                vec![
                    ("name".to_string(), input.name.clone()),
                    ("start_mode".to_string(), (*mode).to_string()),
                ],
                if *mode == current { 1.0 } else { 0.0 },
            );
        }
    }
    if !start_mode.samples.is_empty() {
        out.push(start_mode);
    }

    // state：每个服务 7 项 0/1
    let mut state = MetricFamily::new(
        "windows_service_state",
        "The state of the service (State)",
        MetricType::Gauge,
    );
    for input in inputs {
        for (code, name) in STATE_VALUES {
            state.push_labeled(
                vec![
                    ("name".to_string(), input.name.clone()),
                    ("state".to_string(), (*name).to_string()),
                ],
                if *code == input.state { 1.0 } else { 0.0 },
            );
        }
    }
    if !state.samples.is_empty() {
        out.push(state);
    }

    // process：pid 非 0 且创建时刻已知才输出（Go 的 processStartTime == 0 跳过）
    let mut process = MetricFamily::new(
        "windows_service_process",
        "Process of started service. The value is the creation time of the process as a unix timestamp.",
        MetricType::Gauge,
    );
    for input in inputs {
        if input.pid == 0 {
            continue;
        }
        let Some(start_time) = input.start_time else {
            continue;
        };
        process.push_labeled(
            vec![
                ("name".to_string(), input.name.clone()),
                ("process_id".to_string(), input.pid.to_string()),
            ],
            start_time,
        );
    }
    if !process.samples.is_empty() {
        out.push(process);
    }

    out
}

/// service 采集器：持有 SCM 连接
pub struct ServiceCollector {
    /// SCM 连接（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    scm: Option<crate::ffi::Scm>,
}

impl ServiceCollector {
    /// 默认构造（对齐 Go Build 阶段的 OpenSCManager，仅枚举权限；
    /// 初始化失败保留空连接，collect 时按 NoData 上报）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match crate::ffi::Scm::open() {
                Ok(scm) => Self { scm: Some(scm) },
                Err(error) => {
                    tracing::warn!(%error, "service 采集器 SCM 初始化失败");
                    Self { scm: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for ServiceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ServiceCollector {
    fn name(&self) -> &'static str {
        "service"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        {
            let scm = match &self.scm {
                None => return Err(CollectorError::NoData),
                Some(scm) => scm,
            };
            let entries = scm.services().map_err(super::collector_error)?;
            let mut inputs = Vec::with_capacity(entries.len());
            for entry in entries {
                // 配置不可读按无配置处理；启动类型未知时告警并跳过整服务
                // （对齐 Go 的 "unknown service start mode" 分支）
                let config = match scm.service_config(&entry.name) {
                    Ok(Some(raw)) => match start_mode_name(raw.start_type) {
                        Some(mode) => Some(ServiceSnapshot {
                            display_name: raw.display_name,
                            run_as: raw.run_as,
                            path_name: raw.path_name,
                            start_mode: Some(mode.to_string()),
                        }),
                        None => {
                            tracing::warn!(
                                service = %entry.name,
                                start_type = raw.start_type,
                                "未知的服务启动类型，跳过该服务"
                            );
                            continue;
                        }
                    },
                    Ok(None) => None,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            service = %entry.name,
                            "读取服务配置失败，按无配置处理"
                        );
                        None
                    }
                };
                let start_time = if entry.pid != 0 {
                    crate::ffi::process_create_time_unix(entry.pid)
                } else {
                    None
                };
                inputs.push(ServiceInput {
                    name: entry.name,
                    state: entry.state,
                    pid: entry.pid,
                    start_time,
                    config,
                });
            }
            Ok(emit_service(&inputs))
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造服务输入
    fn input(
        name: &str,
        state: u32,
        pid: u32,
        start_time: Option<f64>,
        with_config: bool,
    ) -> ServiceInput {
        ServiceInput {
            name: name.to_string(),
            state,
            pid,
            start_time,
            config: with_config.then(|| ServiceSnapshot {
                display_name: "Display".to_string(),
                run_as: "LocalSystem".to_string(),
                path_name: r"C:\svc.exe".to_string(),
                start_mode: Some("auto".to_string()),
            }),
        }
    }

    /// 4 个指标族齐全；info 标签与 start_mode/state/process 的条件发射
    #[test]
    fn test_emit_service_family_layout() {
        let inputs = vec![
            input("svc_a", 4, 1234, Some(1_700_000_000.0), true),
            input("svc_b", 1, 0, None, false),
        ];
        let families = emit_service(&inputs);

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "windows_service_info",
                "windows_service_start_mode",
                "windows_service_state",
                "windows_service_process",
            ]
        );

        // info：配置缺失的服务标签取空串
        let info = &families[0];
        assert_eq!(
            info.samples[0].labels,
            vec![
                ("name".to_string(), "svc_a".to_string()),
                ("display_name".to_string(), "Display".to_string()),
                ("run_as".to_string(), "LocalSystem".to_string()),
                ("path_name".to_string(), r"C:\svc.exe".to_string()),
            ]
        );
        assert_eq!(
            info.samples[1].labels,
            vec![
                ("name".to_string(), "svc_b".to_string()),
                ("display_name".to_string(), String::new()),
                ("run_as".to_string(), String::new()),
                ("path_name".to_string(), String::new()),
            ]
        );

        // start_mode：仅配置可读的服务 5 项，当前模式 auto 置 1
        let start_mode = &families[1];
        assert_eq!(start_mode.samples.len(), 5);
        assert!(
            start_mode
                .samples
                .iter()
                .all(|sample| sample.labels[0].1 == "svc_a")
        );
        let current = start_mode
            .samples
            .iter()
            .find(|sample| sample.labels[1].1 == "auto")
            .unwrap_or_else(|| panic!("缺少 auto"));
        assert_eq!(current.value, 1.0);
        let mut others = start_mode
            .samples
            .iter()
            .filter(|sample| sample.labels[1].1 != "auto");
        assert!(others.all(|sample| sample.value == 0.0));

        // state：两个服务各 7 项，svc_a running(4) 置 1
        let state = &families[2];
        assert_eq!(state.samples.len(), 14);
        let running = state
            .samples
            .iter()
            .find(|sample| sample.labels[0].1 == "svc_a" && sample.labels[1].1 == "running")
            .unwrap_or_else(|| panic!("缺少 running"));
        assert_eq!(running.value, 1.0);
        let stopped = state
            .samples
            .iter()
            .find(|sample| sample.labels[0].1 == "svc_b" && sample.labels[1].1 == "stopped")
            .unwrap_or_else(|| panic!("缺少 stopped"));
        assert_eq!(stopped.value, 1.0);

        // process：仅 pid 非 0 且时刻已知的服务
        let process = &families[3];
        assert_eq!(process.samples.len(), 1);
        assert_eq!(
            process.samples[0].labels,
            vec![
                ("name".to_string(), "svc_a".to_string()),
                ("process_id".to_string(), "1234".to_string()),
            ]
        );
        assert_eq!(process.samples[0].value, 1_700_000_000.0);
    }

    /// 配置全部不可读时仍输出 info 与 state，缺 start_mode；pid=0 时不发 process
    #[test]
    fn test_emit_service_without_config() {
        let inputs = vec![input("svc", 7, 0, None, false)];
        let families = emit_service(&inputs);
        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names, vec!["windows_service_info", "windows_service_state"]);

        let state = &families[1];
        let paused = state
            .samples
            .iter()
            .find(|sample| sample.labels[1].1 == "paused")
            .unwrap_or_else(|| panic!("缺少 paused"));
        assert_eq!(paused.value, 1.0);
    }

    /// 空输入不产生指标族
    #[test]
    fn test_emit_service_empty() {
        assert!(emit_service(&[]).is_empty());
    }

    /// 启动类型映射（winsvc.h SERVICE_*_START 常量）
    #[test]
    fn test_start_mode_name() {
        assert_eq!(start_mode_name(2), Some("auto"));
        assert_eq!(start_mode_name(0), Some("boot"));
        assert_eq!(start_mode_name(4), Some("disabled"));
        assert_eq!(start_mode_name(3), Some("manual"));
        assert_eq!(start_mode_name(1), Some("system"));
        assert_eq!(start_mode_name(9), None);
    }
}
