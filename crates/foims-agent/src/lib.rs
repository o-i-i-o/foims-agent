//! FOIMS Agent（Linux/Unix 平台）库入口。
//!
//! 移植约定（详见 docs/agent-porting.md）：
//! - 指标名称/标签/类型与 node_exporter 严格对齐，便于逐项对照验证；
//! - 只读 /proc、/sys 与少量 syscalls（经 rustix 安全封装，crate 内零 unsafe）；
//! - 采集器一律支持 `with_root` 构造，测试可用 node_exporter 的 fixture 数据。
//!
//! 平台职责：提供 Linux 采集器集合（[`default_collectors`]）与
//! [`LinuxPlatform`]（机器标识/采集一帧/续期落盘），上报循环复用
//! `foims_agent_core::reporter::Reporter`。

pub mod collectors;
pub mod platform;

use std::sync::Arc;

use foims_agent_core::collector::{Collector, ScrapeMetrics};

pub use foims_agent_core::{MetricFamily, MetricType, encode_text_all, scrape};
pub use platform::LinuxPlatform;

/// Agent 版本：独立自管理（取 crate 所在 workspace 的共享版本），经
/// --version 与上报快照 agent_version 仅作展示/运维核对，不与主程序
/// 版本绑定。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 缺省配置文件路径
pub const DEFAULT_CONFIG_PATH: &str = "/etc/foims-agent/agent.toml";
/// 缺省证书目录（client.pem / client.key / ca.pem 由安装脚本放置）
pub const DEFAULT_CERT_DIR: &str = "/etc/foims-agent";
/// 证书目录环境变量覆盖（测试/联调用）
pub const ENV_CERT_DIR: &str = "FOIMS_AGENT_CERT_DIR";

/// node 侧抓取附加指标（node_exporter 命名与 help 逐字对齐）
pub const SCRAPE_METRICS: ScrapeMetrics = ScrapeMetrics {
    duration_seconds: "node_scrape_collector_duration_seconds",
    duration_help: "node_exporter: Duration of a collector scrape.",
    success: "node_scrape_collector_success",
    success_help: "node_exporter: Whether a collector succeeded.",
};

/// 构造默认启用的采集器注册表。
///
/// `only` 非空时按名称过滤（对应 node_exporter 的 `--collectors.enabled` 场景，
/// demo 阶段用 `--only` 参数传入）。以 Arc 承载便于超时采集把所有权移入线程。
pub fn default_collectors(only: Option<&[String]>) -> Vec<Arc<dyn Collector>> {
    let all: Vec<Arc<dyn Collector>> = collectors::build_defaults()
        .into_iter()
        .map(Arc::from)
        .collect();
    match only {
        None => all,
        Some(names) => all
            .into_iter()
            .filter(|c| names.iter().any(|n| n == c.name()))
            .collect(),
    }
}
