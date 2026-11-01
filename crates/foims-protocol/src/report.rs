//! Agent 上报协议类型（docs/agent-design.md §3.3）。
//!
//! agent 与服务端共享的请求/响应结构。本文件为主仓 `foims-common/src/report.rs`
//! 的受控副本（工作空间物理隔离），修改字段必须双侧同步，详见 crate 文档。

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

/// 系统信息子结构（agent 采集自 uname/os-release/proc）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportSystem {
    /// 操作系统描述（如 "Ubuntu 22.04 LTS"）。
    pub os: String,
    /// 内核版本。
    pub kernel: String,
    /// 架构标签（如 "x86_64"）。
    pub arch: String,
    /// 开机时长（秒）。
    pub uptime_secs: u64,
}

/// CPU 指标子结构。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportCpu {
    /// 使用率（0-100）。
    pub usage_pct: f64,
    /// 逻辑核心数。
    pub cores: u32,
    /// 1/5/15 分钟负载。
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

/// 内存指标子结构（字节）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportMemory {
    pub total: u64,
    pub used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// 单文件系统/磁盘指标。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportDisk {
    /// 设备名（如 "sda"）。
    pub device: String,
    /// 挂载点（如 "/"）。
    pub mount: String,
    /// 容量与已用（字节）。
    pub total: u64,
    pub used: u64,
    /// 每秒读写次数。
    pub read_iops: f64,
    pub write_iops: f64,
    /// 设备繁忙度（0-100）。
    pub util_pct: f64,
}

/// 单网卡指标。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportNet {
    /// 接口名（如 "eth0"）。
    pub iface: String,
    /// 每秒收发字节数。
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// 累计错误/丢包计数。
    pub errors: u64,
}

/// 单传感器指标。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportSensor {
    /// 传感器标签（如 "coretemp Package id 0"）。
    pub label: String,
    /// 类型：temp | fan | voltage 等。
    pub kind: String,
    /// 读数（温度 ℃ / 风扇 RPM / 电压 V）。
    pub value: f64,
}

/// `POST /agent/v1/report` 请求体（HTTP/3 + Bearer token，§3.3）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentReport {
    /// 机器唯一标识：优先 /etc/machine-id，回退
    /// /var/lib/dbus/machine-id，都没有则首次启动生成本地持久化文件。
    pub machine_id: String,
    /// 主机名。
    pub hostname: String,
    /// agent 版本（semver，用于升级通告展示）。
    pub agent_version: String,
    /// 采集时刻 RFC 3339（如 "2026-10-05T12:00:00Z"）；
    /// 与服务端时间偏差 > 5 分钟拒绝入库。
    pub collected_at: String,
    pub system: ReportSystem,
    pub cpu: ReportCpu,
    pub memory: ReportMemory,
    pub disks: Vec<ReportDisk>,
    pub nets: Vec<ReportNet>,
    pub sensors: Vec<ReportSensor>,
    /// 进程总数。
    pub processes: u32,
}

/// `POST /agent/v1/report` 批量请求体：agent 采集（高频）与上报（低频）解耦后，
/// 一个上报周期内的多帧采集快照打包一次发送。
///
/// 兼容性：单帧 `AgentReport` 仍被服务端接受（旧版 agent 平滑过渡）；
/// 服务端按请求体形态自动区分（含 `frames` 字段视为批量）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentReportBatch {
    /// 本批次帧序列（按采集时间升序；空批次无意义，服务端拒绝）。
    pub frames: Vec<AgentReport>,
    /// 组批以来因本机队列满被丢弃的帧数（观测用，不影响入库）。
    #[serde(default)]
    pub dropped: u64,
}

/// 上报响应控制面：服务端远程调整上报间隔与采集器开关、通告最新版本；
/// agent 下一轮生效。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportResponse {
    /// 下一次上报间隔（秒）。
    pub report_interval: u64,
    /// 采集器开关（键为采集器名）；缺省/缺失视为开启。
    pub collectors: BTreeMap<String, bool>,
    /// 服务端通告的最新 agent 版本（一期仅展示，不做自动升级）。
    pub latest_version: String,
}

/// `POST /agent/v1/renew` 请求体：agent 携带当前客户端证书 PEM 申请续期
/// （mTLS 鉴权，服务端校验请求证书与连接证书一致且剩余寿命低于阈值）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertRenewRequest {
    /// 当前客户端证书 PEM（须与 mTLS 连接呈现的 leaf 证书一致）。
    pub client_cert_pem: String,
}

/// `POST /agent/v1/renew` 响应体：新签发的客户端证书与私钥 PEM。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertRenewResponse {
    /// 新客户端证书 PEM。
    pub cert_pem: String,
    /// 新客户端私钥 PEM（PKCS#8）。
    pub key_pem: String,
    /// 新证书失效时刻 RFC 3339（供 agent 记录下次续期预期）。
    pub not_after: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小合法上报样例，供序列化往返测试复用。
    fn sample_report() -> AgentReport {
        AgentReport {
            machine_id: "3fa85f647c1e4b0f9f5266a8a11d4c7b".to_string(),
            hostname: "web-01".to_string(),
            agent_version: "0.1.2".to_string(),
            collected_at: "2026-10-10T12:00:00Z".to_string(),
            system: ReportSystem {
                os: "Ubuntu 22.04 LTS".to_string(),
                kernel: "5.15.0-91-generic".to_string(),
                arch: "x86_64".to_string(),
                uptime_secs: 864_000,
            },
            cpu: ReportCpu {
                usage_pct: 23.5,
                cores: 8,
                load1: 0.5,
                load5: 0.4,
                load15: 0.3,
            },
            memory: ReportMemory {
                total: 33_619_933_696,
                used: 17_179_869_184,
                swap_total: 2_147_483_648,
                swap_used: 0,
            },
            disks: vec![ReportDisk {
                device: "sda".to_string(),
                mount: "/".to_string(),
                total: 512_110_190_592,
                used: 256_055_095_296,
                read_iops: 12.5,
                write_iops: 30.1,
                util_pct: 4.2,
            }],
            nets: vec![ReportNet {
                iface: "eth0".to_string(),
                rx_bps: 1_048_576.0,
                tx_bps: 524_288.0,
                errors: 0,
            }],
            sensors: vec![ReportSensor {
                label: "coretemp Package id 0".to_string(),
                kind: "temp".to_string(),
                value: 52.0,
            }],
            processes: 231,
        }
    }

    #[test]
    fn report_json_roundtrip() {
        let report = sample_report();
        let json = serde_json::to_string(&report).unwrap_or_default();
        assert!(!json.is_empty());
        let parsed: AgentReport = serde_json::from_str(&json).unwrap_or_else(|_| sample_report());
        assert_eq!(parsed, report);
    }

    #[test]
    fn batch_json_roundtrip() {
        let batch = AgentReportBatch {
            frames: vec![sample_report()],
            dropped: 3,
        };
        let json = serde_json::to_string(&batch).unwrap_or_default();
        let parsed: AgentReportBatch = serde_json::from_str(&json).unwrap_or(batch.clone());
        assert_eq!(parsed, batch);

        // dropped 缺省视为 0（服务端容忍精简请求）
        let minimal: AgentReportBatch = serde_json::from_str(r#"{"frames": []}"#).unwrap_or(batch);
        assert!(minimal.frames.is_empty());
        assert_eq!(minimal.dropped, 0);
    }

    #[test]
    fn response_json_roundtrip() {
        let response = ReportResponse {
            report_interval: 60,
            collectors: BTreeMap::new(),
            latest_version: "0.21.18".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap_or_default();
        let parsed: ReportResponse = serde_json::from_str(&json).unwrap_or(response.clone());
        assert_eq!(parsed, response);
    }

    #[test]
    fn cert_renew_json_roundtrip() {
        let request = CertRenewRequest {
            client_cert_pem: "-----BEGIN CERTIFICATE-----\nabc\n".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap_or_default();
        let parsed: CertRenewRequest = serde_json::from_str(&json).unwrap_or(request.clone());
        assert_eq!(parsed, request);

        let response = CertRenewResponse {
            cert_pem: "-----BEGIN CERTIFICATE-----\nnew\n".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n".to_string(),
            not_after: "2031-10-10T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap_or_default();
        let parsed: CertRenewResponse = serde_json::from_str(&json).unwrap_or(response.clone());
        assert_eq!(parsed, response);
    }
}
