//! 上报冒烟客户端：采集本机指标并经 HTTP/3 mTLS 上报一次，打印服务端响应。
//!
//! 联调前置：准备 cert-dir（client.pem / client.key / ca.pem，可从 Web 端
//! Agent 配置卡片下载安装包解包获取）与服务端（foims-agent-service）。
//!
//! 运行（参数与环境变量两种方式，参数优先）：
//! - `cargo run -p foims-agent --example report_smoke -- 127.0.0.1:9100 <64hex-token> --cert-dir /tmp/certs`
//! - `REPORT_ADDR=127.0.0.1:9100 REPORT_TOKEN=<token> cargo run -p foims-agent --example report_smoke`
//!
//! 成功输出响应状态与 ReportResponse JSON；失败打印错误并以非零码退出。

use std::path::PathBuf;
use std::process::ExitCode;

use foims_agent::{DEFAULT_CERT_DIR, ENV_CERT_DIR, LinuxPlatform};
use foims_agent_core::reporter::{Reporter, ReporterConfig};

/// 统一错误类型（示例简化：装箱任意 Error）
type SmokeError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> ExitCode {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(%error, "冒烟上报失败");
            ExitCode::FAILURE
        }
    }
}

/// 初始化日志：默认 info 级，可用 RUST_LOG 覆盖；全部写入 stderr
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// 读取 `--flag value` 形式的参数值
fn arg_value(args: &[String], flag: &str) -> Result<Option<String>, SmokeError> {
    let Some(index) = args.iter().position(|item| item == flag) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{flag} 缺少参数"))?;
    Ok(Some(value.clone()))
}

fn run(args: Vec<String>) -> Result<ExitCode, SmokeError> {
    // 位置参数优先：addr token；缺省回退环境变量 REPORT_ADDR / REPORT_TOKEN
    let mut positional = args.iter().filter(|arg| !arg.starts_with("--")).cloned();
    let addr = positional
        .next()
        .or_else(|| std::env::var("REPORT_ADDR").ok())
        .ok_or("缺少服务地址：位置参数 host:port 或环境变量 REPORT_ADDR")?;
    let token = positional
        .next()
        .or_else(|| std::env::var("REPORT_TOKEN").ok())
        .ok_or("缺少上报 token：位置参数 64hex 或环境变量 REPORT_TOKEN")?;
    let cert_dir = arg_value(&args, "--cert-dir")?
        .or_else(|| std::env::var(ENV_CERT_DIR).ok())
        .unwrap_or_else(|| DEFAULT_CERT_DIR.to_string());

    let config = ReporterConfig::build(addr, token, None, PathBuf::from(cert_dir))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("构建 tokio 运行时失败: {error}"))?;
    runtime.block_on(async move {
        let mut reporter = Reporter::new(config, LinuxPlatform::new());
        let response = reporter.report_once().await?;
        let json = serde_json::to_string_pretty(&response)
            .map_err(|error| format!("响应编码失败: {error}"))?;
        tracing::info!(status = 200, "上报成功，服务端响应:");
        tracing::info!("\n{json}");
        Ok(ExitCode::SUCCESS)
    })
}
