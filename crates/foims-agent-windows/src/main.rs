//! FOIMS Agent（Windows）可执行入口：本地采集输出 + HTTP/3 mTLS 指标上报。
//!
//! CLI 与 Linux 版逐项对齐，仅默认配置路径/证书目录/平台实现不同：
//! - `foims-agent-windows`：默认 HTTP/3 上报模式
//!   （读取 C:\ProgramData\foims-agent\agent.toml 常驻循环）
//! - `--service`：以 Windows 服务模式运行（SCM 状态机，install.cmd 安装）
//! - `--config PATH`：指定配置文件路径
//! - `--cert-dir DIR`：指定证书目录（或 FOIMS_AGENT_CERT_DIR）
//! - `--once`：采集 + 上报一次即退出（联调/测试）
//! - `--list`：列出已移植的采集器
//! - `--only cpu,memory`：仅启用指定采集器（输出模式）
//! - `--format json`：采集一次，输出 JSON
//! - `--listen 0.0.0.0:9182`：常驻模式，HTTP 提供 /metrics
//!
//! 日志统一走 tracing 输出到 stderr，stdout 只承载指标数据（便于管道/对照验证）。

use std::io::{self, Read, Write as IoWrite};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use foims_agent_core::reporter::{Reporter, ReporterConfig};
use foims_agent_core::{Collector, MetricFamily, encode_text_all, scrape};
use foims_agent_windows::{
    DEFAULT_CERT_DIR, DEFAULT_CONFIG_PATH, ENV_CERT_DIR, VERSION, WindowsPlatform,
    default_collectors,
};

/// 输出格式
#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    /// Prometheus 文本格式（与 windows_exporter 一致）
    Prometheus,
    /// JSON（demo 调试用）
    Json,
}

/// 命令行参数
struct Cli {
    list: bool,
    version: bool,
    only: Option<Vec<String>>,
    /// None 表示未显式指定（区分默认上报模式与一次性输出）
    format: Option<OutputFormat>,
    listen: Option<String>,
    config: Option<String>,
    cert_dir: Option<String>,
    once: bool,
    /// Windows 服务模式（SCM 状态机；服务模式固定常驻上报，忽略
    /// --once/--format/--listen 等一次性/输出参数）
    service: bool,
}

fn main() -> ExitCode {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_cli(&args) {
        Err(message) => {
            stderr_line(&format!("参数错误: {message}"));
            stderr_line(USAGE);
            ExitCode::from(2)
        }
        Ok(cli) => run(cli),
    }
}

const USAGE: &str = "用法: foims-agent-windows [--version] [--list] [--only 名称,名称] [--format prometheus|json] [--listen ADDR:PORT]\n      默认（无 --list/--format/--listen）: HTTP/3 上报模式 [--config PATH] [--cert-dir DIR] [--once]\n      服务模式: --service [--config PATH] [--cert-dir DIR]（由 install.cmd 经 sc.exe 安装，勿手动运行）";

/// 初始化日志：默认 info 级，可用 RUST_LOG 覆盖；写入 stderr 避免污染指标输出
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .init();
}

/// 解析命令行参数
fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        list: false,
        version: false,
        only: None,
        format: None,
        listen: None,
        config: None,
        cert_dir: None,
        once: false,
        service: false,
    };
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--list" => cli.list = true,
            "--version" | "-V" => cli.version = true,
            "--only" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--only 缺少参数".to_string())?;
                let names: Vec<String> = value
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .collect();
                if names.is_empty() {
                    return Err("--only 参数为空".to_string());
                }
                cli.only = Some(names);
            }
            "--format" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--format 缺少参数".to_string())?;
                cli.format = Some(match value.as_str() {
                    "prometheus" | "text" => OutputFormat::Prometheus,
                    "json" => OutputFormat::Json,
                    other => return Err(format!("未知输出格式: {other}")),
                });
            }
            "--listen" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--listen 缺少参数".to_string())?;
                cli.listen = Some(value.clone());
            }
            "--config" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--config 缺少参数".to_string())?;
                cli.config = Some(value.clone());
            }
            "--cert-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--cert-dir 缺少参数".to_string())?;
                cli.cert_dir = Some(value.clone());
            }
            "--once" => cli.once = true,
            "--service" => cli.service = true,
            "--help" | "-h" => {
                stderr_line(USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("未知参数: {other}")),
        }
        index += 1;
    }
    Ok(cli)
}

fn run(cli: Cli) -> ExitCode {
    if cli.list {
        return list_collectors();
    }
    if cli.version {
        // 与 --help 一致走 stderr（本 CLI 约定 stdout 只承载指标数据）
        stderr_line(&format!("foims-agent-windows {VERSION}"));
        return ExitCode::SUCCESS;
    }
    if cli.service {
        // Windows 服务模式：SCM 状态机常驻上报，忽略 --once/--format/--listen
        let (config_path, cert_dir) = resolve_paths(&cli);
        #[cfg(target_os = "windows")]
        {
            return foims_agent_windows::service::run_as_service(&config_path, &cert_dir);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (&config_path, &cert_dir);
            stderr_line("--service 服务模式仅支持 Windows 目标（由 install.cmd 经 sc.exe 安装）");
            return ExitCode::FAILURE;
        }
    }
    // 校验 --only 名称合法性（不存在的名称直接报错，避免静默空输出）
    if let Some(names) = &cli.only {
        let available: Vec<&str> = default_collectors(None).iter().map(|c| c.name()).collect();
        for name in names {
            if !available.contains(&name.as_str()) {
                stderr_line(&format!(
                    "未知采集器: {name}（可用: {}）",
                    available.join(", ")
                ));
                return ExitCode::from(2);
            }
        }
    }
    match (&cli.listen, cli.format) {
        // 常驻 HTTP /metrics 服务（原有语义）
        (Some(addr), _) => {
            let collectors = Arc::new(default_collectors(cli.only.as_deref()));
            match serve(
                addr,
                collectors,
                cli.format.unwrap_or(OutputFormat::Prometheus),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    stderr_line(&message);
                    ExitCode::FAILURE
                }
            }
        }
        // 显式指定输出格式：采集一次输出（原有语义）
        (None, Some(format)) => {
            let collectors = default_collectors(cli.only.as_deref());
            one_shot(&collectors, format)
        }
        // 默认模式：HTTP/3 mTLS 上报
        (None, None) => run_reporter(&cli),
    }
}

/// 从 CLI 解析配置文件与证书目录路径（上报模式与服务模式共用）
fn resolve_paths(cli: &Cli) -> (PathBuf, PathBuf) {
    let config_path = cli
        .config
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let cert_dir = cli
        .cert_dir
        .clone()
        .map(PathBuf::from)
        .or_else(|| std::env::var(ENV_CERT_DIR).ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CERT_DIR));
    (config_path, cert_dir)
}

/// 上报模式：加载配置 → 构建运行时 → 常驻循环或 --once 单次
fn run_reporter(cli: &Cli) -> ExitCode {
    let (config_path, cert_dir) = resolve_paths(cli);
    let config = match ReporterConfig::load(&config_path, cert_dir) {
        Ok(config) => config,
        Err(error) => {
            stderr_line(&format!("加载配置失败: {error}"));
            stderr_line(&format!(
                "提示: 默认上报模式需要 agent 配置文件（缺省 {DEFAULT_CONFIG_PATH}，含 server_addr/token），\
                 或用 --config 指定路径；仅本地输出请使用 --format prometheus"
            ));
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            stderr_line(&format!("构建 tokio 运行时失败: {error}"));
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let mut reporter = Reporter::new(config, WindowsPlatform::new());
        if cli.once {
            match reporter.report_once().await {
                Ok(response) => {
                    tracing::info!(
                        interval = response.report_interval,
                        latest_version = %response.latest_version,
                        "单次上报完成"
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    stderr_line(&format!("上报失败: {error}"));
                    ExitCode::FAILURE
                }
            }
        } else {
            reporter.run().await;
            ExitCode::SUCCESS
        }
    })
}

/// 列出全部已移植采集器（每行一个，便于脚本处理）
fn list_collectors() -> ExitCode {
    let mut out = io::stdout().lock();
    for collector in default_collectors(None) {
        if let Err(error) = writeln!(out, "{}", collector.name()) {
            stderr_line(&format!("输出失败: {error}"));
            return ExitCode::FAILURE;
        }
    }
    if out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// 采集一次并输出到 stdout
fn one_shot(collectors: &[Arc<dyn Collector>], format: OutputFormat) -> ExitCode {
    let families = scrape(collectors, &foims_agent_windows::SCRAPE_METRICS);
    let text = match render(&families, format) {
        Ok(text) => text,
        Err(message) => {
            stderr_line(&message);
            return ExitCode::FAILURE;
        }
    };
    let mut out = io::stdout().lock();
    if let Err(error) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        stderr_line(&format!("输出失败: {error}"));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// 按指定格式渲染指标
fn render(families: &[MetricFamily], format: OutputFormat) -> Result<String, String> {
    match format {
        OutputFormat::Prometheus => Ok(encode_text_all(families)),
        OutputFormat::Json => {
            let value = serde_json::json!(
                families
                    .iter()
                    .map(|family| serde_json::json!({
                        "name": family.name,
                        "help": family.help,
                        "type": family.mtype.as_str(),
                        "samples": family
                            .samples
                            .iter()
                            .map(|sample| serde_json::json!({
                                "labels": sample
                                    .labels
                                    .iter()
                                    .cloned()
                                    .collect::<std::collections::BTreeMap<String, String>>(),
                                "value": sample.value,
                            }))
                            .collect::<Vec<serde_json::Value>>(),
                    }))
                    .collect::<Vec<serde_json::Value>>()
            );
            serde_json::to_string_pretty(&value).map_err(|error| format!("JSON 编码失败: {error}"))
        }
    }
}

/// 常驻模式：极简 HTTP/1.1 服务，GET /metrics 返回指标
fn serve(
    addr: &str,
    collectors: Arc<Vec<Arc<dyn Collector>>>,
    format: OutputFormat,
) -> Result<(), String> {
    let listener =
        std::net::TcpListener::bind(addr).map_err(|error| format!("绑定 {addr} 失败: {error}"))?;
    tracing::info!(
        addr,
        version = VERSION,
        "foims-agent-windows HTTP 服务已启动"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // 采集可能占用 CPU，超量并发抓取会拖垮整机：达到上限直接拒收
                if ACTIVE_CONNS.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNS {
                    tracing::warn!("并发连接达到上限 {MAX_CONCURRENT_CONNS}，拒绝新连接");
                    continue;
                }
                ACTIVE_CONNS.fetch_add(1, Ordering::Relaxed);
                let collectors = Arc::clone(&collectors);
                std::thread::spawn(move || {
                    handle_conn(stream, collectors, format);
                    ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(error) => tracing::warn!(%error, "接受连接失败"),
        }
    }
    Ok(())
}

/// 同时处理的连接数上限
const MAX_CONCURRENT_CONNS: usize = 32;
/// 套接字读写超时：防止慢客户端（不发请求/不收响应）长期占用线程
const CONN_TIMEOUT: Duration = Duration::from_secs(10);

static ACTIVE_CONNS: AtomicUsize = AtomicUsize::new(0);

/// 处理单个 HTTP 连接（demo 实现：仅解析请求行，不持久连接）
fn handle_conn(
    mut stream: TcpStream,
    collectors: Arc<Vec<Arc<dyn Collector>>>,
    format: OutputFormat,
) {
    if let Err(error) = stream.set_read_timeout(Some(CONN_TIMEOUT)) {
        tracing::debug!(%error, "设置读超时失败");
        return;
    }
    if let Err(error) = stream.set_write_timeout(Some(CONN_TIMEOUT)) {
        tracing::debug!(%error, "设置写超时失败");
        return;
    }
    let mut buffer = [0u8; 4096];
    let read = match stream.read(&mut buffer) {
        Ok(read) => read,
        Err(error) => {
            tracing::debug!(%error, "读取请求失败");
            return;
        }
    };
    let request = String::from_utf8_lossy(&buffer[..read]);
    // 请求行形如 "GET /metrics?x=1 HTTP/1.1"，取中间的路径并去掉查询串
    let raw_path = request.split_whitespace().nth(1).unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/");

    let (status, content_type, body) = match path {
        "/metrics" => {
            let families = scrape(&collectors, &foims_agent_windows::SCRAPE_METRICS);
            match render(&families, format) {
                Ok(text) => ("200 OK", metrics_content_type(format), text),
                Err(message) => (
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    format!("渲染失败: {message}\n"),
                ),
            }
        }
        "/" => ("200 OK", "text/plain; charset=utf-8", landing_page()),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "404 page not found\n".to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if let Err(error) = stream.write_all(response.as_bytes()) {
        tracing::debug!(%error, "写出响应失败");
    }
}

/// /metrics 的 Content-Type（Prometheus 文本格式带版本标识）
fn metrics_content_type(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Prometheus => "text/plain; version=0.0.4; charset=utf-8",
        OutputFormat::Json => "application/json; charset=utf-8",
    }
}

/// 根路径的简版说明页
fn landing_page() -> String {
    let mut page = String::new();
    page.push_str("<html><head><title>FOIMS Agent (Windows)</title></head><body>\n");
    page.push_str(
        "<h1>FOIMS Agent (Windows)</h1>\n<p>windows_exporter 的 Rust 移植（FOIMS Agent）。</p>\n",
    );
    page.push_str("<p><a href=\"/metrics\">Metrics</a></p>\n");
    page.push_str("</body></html>\n");
    page
}

/// 写一行到 stderr（clippy print_stderr 护栏下的统一出口）
fn stderr_line(message: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_defaults() {
        let cli = parse_cli(&[]).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(!cli.list);
        assert!(!cli.version);
        assert!(cli.only.is_none());
        assert!(cli.listen.is_none());
        assert!(cli.format.is_none());
        assert!(cli.config.is_none());
        assert!(cli.cert_dir.is_none());
        assert!(!cli.once);
        assert!(!cli.service);
    }

    #[test]
    fn test_parse_cli_version_flag() {
        let args = vec!["--version".to_string()];
        let cli = parse_cli(&args).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(cli.version);
    }

    #[test]
    fn test_parse_cli_full() {
        let args: Vec<String> = vec![
            "--only",
            "cpu, memory",
            "--format",
            "json",
            "--listen",
            "0.0.0.0:9182",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let cli = parse_cli(&args).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(
            cli.only,
            Some(vec!["cpu".to_string(), "memory".to_string()])
        );
        assert_eq!(cli.listen.as_deref(), Some("0.0.0.0:9182"));
        assert!(matches!(cli.format, Some(OutputFormat::Json)));
    }

    #[test]
    fn test_parse_cli_reporter_flags() {
        let args: Vec<String> = vec![
            "--config",
            r"C:\Temp\agent.toml",
            "--cert-dir",
            r"C:\Temp\certs",
            "--once",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let cli = parse_cli(&args).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(cli.config.as_deref(), Some(r"C:\Temp\agent.toml"));
        assert_eq!(cli.cert_dir.as_deref(), Some(r"C:\Temp\certs"));
        assert!(cli.once);
        // 上报模式判定：无 --list/--format/--listen
        assert!(cli.listen.is_none() && cli.format.is_none() && !cli.list);
    }

    #[test]
    fn test_parse_cli_service_flag() {
        let args = vec!["--service".to_string()];
        let cli = parse_cli(&args).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(cli.service);
        // 服务模式可与 --config/--cert-dir 共存（运行期忽略 --once 等输出参数）
        let args2: Vec<String> = vec!["--service", "--config", r"C:\Temp\agent.toml"]
            .into_iter()
            .map(String::from)
            .collect();
        let cli2 = parse_cli(&args2).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(cli2.service);
        assert_eq!(cli2.config.as_deref(), Some(r"C:\Temp\agent.toml"));
    }

    #[test]
    fn test_parse_cli_rejects_unknown() {
        let args = vec!["--bogus".to_string()];
        assert!(parse_cli(&args).is_err());
    }
}
