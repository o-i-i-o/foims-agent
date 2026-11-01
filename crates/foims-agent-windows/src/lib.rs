//! FOIMS Agent（Windows 平台）库入口。
//!
//! 移植约定（详见 docs/agent-porting.md Windows 批次表）：
//! - 指标名称/标签/类型与 windows_exporter 严格对齐，便于逐项对照验证；
//! - 默认启用集与 windows_exporter 默认配置一致：cpu / logical_disk /
//!   memory / net / os / physical_disk / service / system 共 8 个采集器；
//! - FFI 调用（PDH/注册表/SCM）以 `ffi` 模块封装并用
//!   `cfg(target_os = "windows")` 门控，纯解析/计算逻辑拆出以便在
//!   Linux 宿主运行单测；
//! - 上报循环复用 `foims_agent_core::reporter::Reporter`。

pub mod collectors;
pub mod ffi;
pub mod platform;
// Windows SCM 服务模式：仅 windows 目标编译（Linux 宿主无 SCM 概念）
#[cfg(target_os = "windows")]
pub mod service;

use std::sync::Arc;

use foims_agent_core::collector::{Collector, ScrapeMetrics};

pub use platform::WindowsPlatform;

/// Agent 版本：与 Linux 平台共享 workspace 版本，独立自管理。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 缺省配置文件路径（Windows 惯例：ProgramData）
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\foims-agent\agent.toml";
/// 缺省证书目录（client.pem / client.key / ca.pem 由安装脚本放置）
pub const DEFAULT_CERT_DIR: &str = r"C:\ProgramData\foims-agent";
/// 证书目录环境变量覆盖（测试/联调用）
pub const ENV_CERT_DIR: &str = "FOIMS_AGENT_CERT_DIR";

/// windows 侧抓取附加指标（windows_exporter 命名与 help 逐字对齐，见
/// pkg/collector/collection.go 的 collectorScrapeDurationDesc /
/// collectorScrapeSuccessDesc）
pub const SCRAPE_METRICS: ScrapeMetrics = ScrapeMetrics {
    duration_seconds: "windows_exporter_collector_duration_seconds",
    duration_help: "windows_exporter: Duration of a collection.",
    success: "windows_exporter_collector_success",
    success_help: "windows_exporter: Whether the collector was successful.",
};

/// 构造默认启用的采集器注册表。
///
/// `only` 非空时按名称过滤（对应 windows_exporter 的 enabled 采集器
/// 场景，demo 阶段用 `--only` 参数传入）。以 Arc 承载便于超时采集把
/// 所有权移入线程。
pub fn default_collectors(only: Option<&[String]>) -> Vec<Arc<dyn Collector>> {
    let all: Vec<Arc<dyn Collector>> = collectors::build_defaults();
    match only {
        None => all,
        Some(names) => all
            .into_iter()
            .filter(|collector| names.iter().any(|name| name == collector.name()))
            .collect(),
    }
}
