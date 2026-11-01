//! 采集器框架：trait 定义、错误类型、注册表与抓取编排。
//!
//! 对齐 node_exporter 的语义：
//! - 每个采集器实现 [`Collector`]，名称与 node_exporter 保持一致，便于逐项对照移植；
//! - 每次抓取附加 `node_scrape_collector_duration_seconds` 与
//!   `node_scrape_collector_success`（与原版 execute() 行为一致：NoData 也计为失败）。
//!
//! 采集以独立线程执行并施加超时：NFS 死挂载等阻塞系统调用无法被中断，
//! 超时后放弃等待（线程留在内核态无法回收），采集器进入冷却期避免每轮
//! 抓取都派生新的卡死线程拖垮上报主循环。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::metric::MetricFamily;

/// 单采集器超时：超过该时长视为卡死（正常采集均在毫秒级）
const COLLECT_TIMEOUT: Duration = Duration::from_secs(30);
/// 卡死采集器冷却期：期间跳过采集，冷却后重试
const HUNG_COOLDOWN: Duration = Duration::from_secs(600);

/// 采集器统一接口（对应 node_exporter 的 `Collector.Update(ch)`）
pub trait Collector: Send + Sync {
    /// 采集器名称（与 node_exporter 一致）
    fn name(&self) -> &'static str;
    /// 执行一次采集；无数据可采时返回 [`CollectorError::NoData`]（不算失败启动）
    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError>;
}

/// 采集错误类型
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("解析失败 {file}: {reason}")]
    Parse { file: &'static str, reason: String },
    #[error("采集器无数据")]
    NoData,
}

/// 卡死采集器登记表（名称 → 判定时刻）。
///
/// Mutex 中毒视为不可恢复异常之外的场景：直接取回内部数据继续工作
/// （登记表仅用于限流，不应因某次 panic 永久失效）。
fn hung_collectors() -> &'static Mutex<HashMap<&'static str, Instant>> {
    static HUNG: OnceLock<Mutex<HashMap<&'static str, Instant>>> = OnceLock::new();
    HUNG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 构造默认启用的采集器注册表（Linux）。
///
/// `only` 非空时按名称过滤（对应 node_exporter 的 `--collectors.enabled` 场景，
/// demo 阶段用 `--only` 参数传入）。以 Arc 承载便于超时采集把所有权移入线程。
pub fn default_collectors(only: Option<&[String]>) -> Vec<Arc<dyn Collector>> {
    let all: Vec<Arc<dyn Collector>> = crate::collectors::build_defaults()
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

/// 带超时执行单个采集器，返回 (成功标记, 指标族)。
///
/// 冷却期内的卡死采集器直接跳过（不再派生注定阻塞的线程）；
/// 超时线程因阻塞在内核态无法回收，属于放弃等待的有意代价。
fn collect_with_timeout(collector: Arc<dyn Collector>) -> (f64, Vec<MetricFamily>) {
    let name = collector.name();
    {
        let mut hung = hung_collectors()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hung.retain(|_, hung_at| hung_at.elapsed() < HUNG_COOLDOWN);
        if hung.contains_key(&name) {
            tracing::debug!(collector = name, "采集器处于卡死冷却期，跳过");
            return (0.0, Vec::new());
        }
    }

    let (tx, rx) = mpsc::channel();
    let worker = match std::thread::Builder::new()
        .name(format!("collect-{name}"))
        .spawn(move || {
            // 接收端可能已因超时被放弃，发送失败属预期
            let _ = tx.send(collector.collect());
        }) {
        Ok(worker) => worker,
        Err(error) => {
            tracing::warn!(collector = name, error = %error, "采集线程创建失败");
            return (0.0, Vec::new());
        }
    };
    // 不 join：超时场景必须能够放弃等待，JoinHandle 丢弃即分离线程
    drop(worker);

    match rx.recv_timeout(COLLECT_TIMEOUT) {
        Ok(Ok(families)) => (1.0, families),
        Ok(Err(CollectorError::NoData)) => {
            tracing::debug!(collector = name, "采集器无数据");
            (0.0, Vec::new())
        }
        Ok(Err(error)) => {
            tracing::warn!(collector = name, error = %error, "采集器失败");
            (0.0, Vec::new())
        }
        Err(_) => {
            hung_collectors()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(name, Instant::now());
            tracing::warn!(
                collector = name,
                timeout_secs = COLLECT_TIMEOUT.as_secs(),
                "采集器超时（疑似挂载点卡死），进入冷却期"
            );
            (0.0, Vec::new())
        }
    }
}

/// 执行一次完整抓取：逐个调用采集器并附加抓取耗时/成功标记指标族。
pub fn scrape(collectors: &[Arc<dyn Collector>]) -> Vec<MetricFamily> {
    let mut out = Vec::new();
    for collector in collectors {
        let begin = Instant::now();
        let (success, mut families) = collect_with_timeout(Arc::clone(collector));
        let duration = begin.elapsed().as_secs_f64();
        let name = collector.name();
        out.append(&mut families);

        let mut duration_family = MetricFamily::new(
            "node_scrape_collector_duration_seconds",
            "node_exporter: Duration of a collector scrape.",
            crate::metric::MetricType::Gauge,
        );
        duration_family.push_labeled(vec![("collector".to_string(), name.to_string())], duration);
        out.push(duration_family);

        let mut success_family = MetricFamily::new(
            "node_scrape_collector_success",
            "node_exporter: Whether a collector succeeded.",
            crate::metric::MetricType::Gauge,
        );
        success_family.push_labeled(vec![("collector".to_string(), name.to_string())], success);
        out.push(success_family);
    }
    out
}
