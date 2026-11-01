//! FOIMS Agent 平台无关层。
//!
//! - [`metric`]：Prometheus 风格指标模型与文本编码；
//! - [`collector`]：采集器 trait、抓取编排与卡死冷却；
//! - [`reporter`]：HTTP/3 mTLS 上报 transport 与 [`reporter::Platform`]
//!   集成契约（采集上报解耦/批量上报/连接复用/退避/断网缓存/证书续期）。
//!
//! 平台 crate（Linux/Windows）实现 [`reporter::Platform`] 并提供具体
//! 采集器集合；本 crate 不感知任何平台细节。

pub mod collector;
pub mod metric;
pub mod reporter;

pub use collector::{Collector, CollectorError, ScrapeMetrics, scrape};
pub use metric::{MetricFamily, MetricType, encode_text_all};
