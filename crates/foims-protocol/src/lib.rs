//! FOIMS Agent 上报协议 crate：请求/响应结构与证书剩余寿命解析。
//!
//! ## 同步义务（重要）
//!
//! 本 crate 是主仓 `foims-common` 中 `report.rs` / `x509.rs` 的**双副本**
//! （agent 工作空间与主程序工作空间物理隔离后，跨仓共享类型以受控副本
//! 维护）。修改协议字段或解析口径时必须双侧同步：
//!
//! - `crates/foims-protocol/src/report.rs` ⇄ 主仓 `crates/foims-common/src/report.rs`
//! - `crates/foims-protocol/src/x509.rs`   ⇄ 主仓 `crates/foims-common/src/x509.rs`
//!
//! 服务端反序列化容错以本结构为准（未知字段 `deny`/`ignore` 行为、字段
//! 重命名、类型宽窄化都会影响线上兼容性），改动前先确认服务端解析逻辑。

pub mod report;
pub mod x509;
