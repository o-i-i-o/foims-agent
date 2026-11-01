//! 采集器框架：trait 定义、错误类型与抓取编排（平台无关）。
//!
//! 对齐 node_exporter 的语义：
//! - 每个采集器实现 [`Collector`]，名称与源项目保持一致，便于逐项对照移植；
//! - 每次抓取附加抓取耗时与成功标记指标族（名称由 [`ScrapeMetrics`] 注入，
//!   node 侧为 `node_scrape_collector_*`，windows 侧为
//!   `windows_exporter_collector_*`；NoData 也计为失败，与原版一致）。
//!
//! 采集以独立线程执行并施加超时：NFS 死挂载等阻塞系统调用无法被中断，
//! 超时后放弃等待（线程留在内核态无法回收），采集器进入冷却期避免每轮
//! 抓取都派生新的卡死线程拖垮上报主循环。
//!
//! 平台 crate 职责：提供具体采集器集合（如 node 的 `default_collectors`），
//! 本 crate 不感知任何平台注册表。

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

/// 抓取附加指标名与 help 文本（命名/help 随源项目约定逐字对齐：
/// node_exporter → `node_scrape_collector_*`，windows_exporter →
/// `windows_exporter_collector_*`）
#[derive(Debug, Clone, Copy)]
pub struct ScrapeMetrics {
    /// 单采集器抓取耗时（秒，gauge，标签 collector）
    pub duration_seconds: &'static str,
    /// 耗时指标 help 文本
    pub duration_help: &'static str,
    /// 单采集器抓取成功标记（1/0，gauge，标签 collector）
    pub success: &'static str,
    /// 成功标记指标 help 文本
    pub success_help: &'static str,
}

/// 采集器统一接口（对应 node_exporter 的 `Collector.Update(ch)`）
pub trait Collector: Send + Sync {
    /// 采集器名称（与源项目一致）
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
pub fn scrape(collectors: &[Arc<dyn Collector>], metrics: &ScrapeMetrics) -> Vec<MetricFamily> {
    let mut out = Vec::new();
    for collector in collectors {
        let begin = Instant::now();
        let (success, mut families) = collect_with_timeout(Arc::clone(collector));
        let duration = begin.elapsed().as_secs_f64();
        let name = collector.name();
        out.append(&mut families);

        let mut duration_family = MetricFamily::new(
            metrics.duration_seconds,
            metrics.duration_help,
            crate::metric::MetricType::Gauge,
        );
        duration_family.push_labeled(vec![("collector".to_string(), name.to_string())], duration);
        out.push(duration_family);

        let mut success_family = MetricFamily::new(
            metrics.success,
            metrics.success_help,
            crate::metric::MetricType::Gauge,
        );
        success_family.push_labeled(vec![("collector".to_string(), name.to_string())], success);
        out.push(success_family);
    }
    out
}
