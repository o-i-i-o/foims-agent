//! Windows 平台实现：机器标识、指标采集与报告组装、续期产物落盘。
//!
//! 实现 [`Platform`] 三件事，上报循环与其余传输逻辑全部复用
//! `foims_agent_core::reporter::Reporter`：
//! - 机器标识：注册表 MachineGuid，缺失/读取失败回退内存随机 uuid v4
//!   （告警提示，进程重启会变化）；
//! - 采集：`default_collectors` 抓取 windows_* 指标，CPU 使用率取帧内
//!   200ms 差分，logical_disk/net 累计计数器跨帧差分为 IOPS 与 bps，
//!   差分状态保存在本结构内；
//! - 续期落盘：临时文件 + rename 原子替换（Windows 无 chmod 语义，
//!   新文件继承目录 ACL）。
//!
//! 报告映射：内存用物理内存（swap 字段以提交量近似）、磁盘 device/mount
//! 取卷名（mount 优先 info 的 volume_name）、网络 errors 取累计错误数、
//! 负载恒 0（Windows 无 loadavg 概念）、传感器为空（暂无对应采集器）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use foims_agent_core::collector::scrape;
use foims_agent_core::metric::{MetricFamily, Sample};
use foims_agent_core::reporter::{Platform, ReporterError};
use foims_protocol::report::{
    AgentReport, ReportCpu, ReportDisk, ReportMemory, ReportNet, ReportSystem,
};

use crate::VERSION;
use crate::default_collectors;

/// CPU 使用率两次采样窗口
const CPU_SAMPLE_WINDOW: Duration = Duration::from_millis(200);

/// logical_disk 累计计数器（IOPS/util 差分基准）
#[derive(Debug, Clone, Copy, Default)]
struct DiskCounters {
    reads: f64,
    writes: f64,
    idle_secs: f64,
}

/// net 累计计数器（bps 差分基准）
#[derive(Debug, Clone, Copy, Default)]
struct NetCounters {
    rx_bytes: f64,
    tx_bytes: f64,
}

/// 上轮差分基准：logical_disk/net 计数器 + 采样时刻
#[derive(Debug, Clone, Default)]
struct DiffBasis {
    at: Option<Instant>,
    disks: BTreeMap<String, DiskCounters>,
    nets: BTreeMap<String, NetCounters>,
}

/// CPU 聚合差分样本（core="_Total" 行，单位秒）
#[derive(Debug, Clone, Copy, PartialEq)]
struct CpuSample {
    /// 5 种模式（dpc/idle/interrupt/privileged/user）之和
    total: f64,
    /// mode=idle
    idle: f64,
}

/// 从 windows_cpu_time_total 提取聚合样本（core="_Total" 行）
fn cpu_sample_from_families(families: &[MetricFamily]) -> Option<CpuSample> {
    let family = find_family(families, "windows_cpu_time_total")?;
    let mut total = 0.0;
    let mut idle = None;
    for sample in &family.samples {
        if label_value(sample, "core") != Some("_Total") {
            continue;
        }
        total += sample.value;
        if label_value(sample, "mode") == Some("idle") {
            idle = Some(sample.value);
        }
    }
    Some(CpuSample { total, idle: idle? })
}

/// 两次采样差分得使用率（0-100）；时间倒流或无推进时按 0 处理
fn cpu_usage_pct(prev: &CpuSample, curr: &CpuSample) -> f64 {
    let dt = curr.total - prev.total;
    if dt <= 0.0 {
        return 0.0;
    }
    let idle = curr.idle - prev.idle;
    ((1.0 - idle / dt) * 100.0).clamp(0.0, 100.0)
}

/// logical_disk 计数器差分 → (read_iops, write_iops, util_pct)；
/// 计数回绕/重置（curr < prev）或间隔非正时按 0 处理
fn disk_rates(prev: &DiskCounters, curr: &DiskCounters, elapsed_secs: f64) -> (f64, f64, f64) {
    if elapsed_secs <= 0.0 {
        return (0.0, 0.0, 0.0);
    }
    let read_delta = curr.reads - prev.reads;
    let write_delta = curr.writes - prev.writes;
    let idle_delta = curr.idle_secs - prev.idle_secs;
    if read_delta < 0.0 || write_delta < 0.0 || idle_delta < 0.0 {
        return (0.0, 0.0, 0.0);
    }
    (
        read_delta / elapsed_secs,
        write_delta / elapsed_secs,
        ((1.0 - idle_delta / elapsed_secs) * 100.0).clamp(0.0, 100.0),
    )
}

/// net 字节差分 → (rx_bps, tx_bps)；回绕/重置按 0 处理
fn net_rates(prev: &NetCounters, curr: &NetCounters, elapsed_secs: f64) -> (f64, f64) {
    if elapsed_secs <= 0.0 {
        return (0.0, 0.0);
    }
    let rx = curr.rx_bytes - prev.rx_bytes;
    let tx = curr.tx_bytes - prev.tx_bytes;
    if rx < 0.0 || tx < 0.0 {
        return (0.0, 0.0);
    }
    (rx / elapsed_secs, tx / elapsed_secs)
}

/// 指标族查找（按名）
fn find_family<'a>(families: &'a [MetricFamily], name: &str) -> Option<&'a MetricFamily> {
    families.iter().find(|family| family.name == name)
}

/// 单样本取值（缺失按 0，采集失败不应让上报中断）
fn sample_value(families: &[MetricFamily], name: &str) -> f64 {
    find_family(families, name)
        .and_then(|family| family.samples.first())
        .map(|sample| sample.value)
        .unwrap_or(0.0)
}

/// 取样本指定标签值
fn label_value<'a>(sample: &'a Sample, key: &str) -> Option<&'a str> {
    sample
        .labels
        .iter()
        .find(|(key_candidate, _)| key_candidate == key)
        .map(|(_, value)| value.as_str())
}

/// 按多标签精确匹配样本
fn find_labeled<'a>(
    families: &'a [MetricFamily],
    name: &str,
    want: &[(&str, &str)],
) -> Option<&'a Sample> {
    find_family(families, name)?.samples.iter().find(|sample| {
        want.iter()
            .all(|(key, value)| label_value(sample, key) == Some(*value))
    })
}

/// 取指标族首样本的指定标签值
fn first_label(families: &[MetricFamily], name: &str, key: &str) -> Option<String> {
    find_family(families, name)?
        .samples
        .first()
        .and_then(|sample| label_value(sample, key))
        .map(str::to_string)
}

/// 从 logical_disk 三族指标收集各卷计数器（{volume} 标签）
fn collect_disk_counters(families: &[MetricFamily]) -> BTreeMap<String, DiskCounters> {
    let mut counters: BTreeMap<String, DiskCounters> = BTreeMap::new();
    let mut insert =
        |families: &[MetricFamily], name: &str, pick: fn(&mut DiskCounters) -> &mut f64| {
            if let Some(family) = find_family(families, name) {
                for sample in &family.samples {
                    if let Some(volume) = label_value(sample, "volume") {
                        *pick(counters.entry(volume.to_string()).or_default()) = sample.value;
                    }
                }
            }
        };
    insert(families, "windows_logical_disk_reads_total", |counters| {
        &mut counters.reads
    });
    insert(families, "windows_logical_disk_writes_total", |counters| {
        &mut counters.writes
    });
    insert(
        families,
        "windows_logical_disk_idle_seconds_total",
        |counters| &mut counters.idle_secs,
    );
    counters
}

/// 从 net 两族指标收集各接口字节计数器（{nic} 标签）
fn collect_net_counters(families: &[MetricFamily]) -> BTreeMap<String, NetCounters> {
    let mut counters: BTreeMap<String, NetCounters> = BTreeMap::new();
    let mut insert =
        |families: &[MetricFamily], name: &str, pick: fn(&mut NetCounters) -> &mut f64| {
            if let Some(family) = find_family(families, name) {
                for sample in &family.samples {
                    if let Some(iface) = label_value(sample, "nic") {
                        *pick(counters.entry(iface.to_string()).or_default()) = sample.value;
                    }
                }
            }
        };
    insert(families, "windows_net_bytes_received_total", |counters| {
        &mut counters.rx_bytes
    });
    insert(families, "windows_net_bytes_sent_total", |counters| {
        &mut counters.tx_bytes
    });
    counters
}

/// 单接口累计错误数（{nic} 标签，收发两族共用）
fn interface_errors(families: &[MetricFamily], name: &str, iface: &str) -> f64 {
    find_labeled(families, name, &[("nic", iface)])
        .map(|sample| sample.value)
        .unwrap_or(0.0)
}

/// logical_disk 容量 + 计数器差分 → ReportDisk 列表
/// （device/mount 均取卷名；mount 优先 info 的 volume_name 标签，
/// 首轮无基准或无法匹配的卷 IOPS/util 记 0）
fn build_disks(
    families: &[MetricFamily],
    diskstats: &BTreeMap<String, DiskCounters>,
    prev: Option<&BTreeMap<String, DiskCounters>>,
    elapsed_secs: f64,
) -> Vec<ReportDisk> {
    let Some(size_family) = find_family(families, "windows_logical_disk_size_bytes") else {
        return Vec::new();
    };
    let mut disks = Vec::new();
    for size_sample in &size_family.samples {
        let Some(volume) = label_value(size_sample, "volume") else {
            continue;
        };
        let total = size_sample.value.max(0.0) as u64;
        let free = find_labeled(
            families,
            "windows_logical_disk_free_bytes",
            &[("volume", volume)],
        )
        .map(|sample| sample.value)
        .unwrap_or(0.0);
        let used = (size_sample.value - free).max(0.0) as u64;

        let mount = find_labeled(families, "windows_logical_disk_info", &[("volume", volume)])
            .and_then(|sample| label_value(sample, "volume_name"))
            .filter(|text| !text.is_empty())
            .unwrap_or(volume);
        let (read_iops, write_iops, util_pct) = match (
            prev.and_then(|basis| basis.get(volume)),
            diskstats.get(volume),
        ) {
            (Some(prev_counters), Some(curr_counters)) => {
                disk_rates(prev_counters, curr_counters, elapsed_secs)
            }
            _ => (0.0, 0.0, 0.0),
        };
        disks.push(ReportDisk {
            device: volume.to_string(),
            mount: mount.to_string(),
            total,
            used,
            read_iops,
            write_iops,
            util_pct,
        });
    }
    disks
}

/// net 字节差分 → ReportNet 列表（首轮无基准 bps 记 0，errors 取累计值）
fn build_nets(
    families: &[MetricFamily],
    netdev: &BTreeMap<String, NetCounters>,
    prev: Option<&BTreeMap<String, NetCounters>>,
    elapsed_secs: f64,
) -> Vec<ReportNet> {
    let mut nets = Vec::new();
    for (iface, curr_counters) in netdev {
        let (rx_bps, tx_bps) = match prev.and_then(|basis| basis.get(iface)) {
            Some(prev_counters) => net_rates(prev_counters, curr_counters, elapsed_secs),
            None => (0.0, 0.0),
        };
        let errors =
            (interface_errors(families, "windows_net_packets_received_errors_total", iface)
                + interface_errors(families, "windows_net_packets_outbound_errors_total", iface))
            .max(0.0) as u64;
        nets.push(ReportNet {
            iface: iface.clone(),
            rx_bps,
            tx_bps,
            errors,
        });
    }
    nets
}

/// 逻辑核心数：windows_cpu_time_total mode=user 的样本数（剔除 _Total
/// 聚合行，与 Linux 端每核一条的口径对齐）
fn count_cores(families: &[MetricFamily]) -> u32 {
    find_family(families, "windows_cpu_time_total")
        .map(|family| {
            family
                .samples
                .iter()
                .filter(|sample| {
                    label_value(sample, "mode") == Some("user")
                        && label_value(sample, "core") != Some("_Total")
                })
                .count() as u32
        })
        .unwrap_or(0)
}

/// RFC3339 UTC 当前时刻（如 "2026-10-15T00:00:00Z"）
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 由 scrape 输出组装 AgentReport，并产出新差分基准（logical_disk/net）
fn build_report(
    machine_id: &str,
    prev: Option<DiffBasis>,
    families: &[MetricFamily],
    sample_at: Instant,
    usage_pct: f64,
) -> (AgentReport, DiffBasis) {
    let now = now_rfc3339();

    // 差分：与上轮计数器对比（首轮无基准，速率记 0）
    let prev = prev.unwrap_or_default();
    let elapsed = prev
        .at
        .map(|at| sample_at.duration_since(at).as_secs_f64())
        .unwrap_or(0.0);

    // 内存（swap 字段以提交量近似）
    let memory = ReportMemory {
        total: sample_value(families, "windows_memory_physical_total_bytes").max(0.0) as u64,
        used: (sample_value(families, "windows_memory_physical_total_bytes")
            - sample_value(families, "windows_memory_available_bytes"))
        .max(0.0) as u64,
        swap_total: sample_value(families, "windows_memory_commit_limit_bytes").max(0.0) as u64,
        swap_used: sample_value(families, "windows_memory_committed_bytes").max(0.0) as u64,
    };

    // 磁盘：logical_disk 容量 + 计数器差分
    let diskstats = collect_disk_counters(families);
    // 首轮 elapsed 为 0，差分自动归 0，无需特判空基准
    let disks = build_disks(families, &diskstats, Some(&prev.disks), elapsed);

    // 网络：net 字节计数器差分
    let netdev = collect_net_counters(families);
    let nets = build_nets(families, &netdev, Some(&prev.nets), elapsed);

    // 更新差分基准
    let basis = DiffBasis {
        at: Some(sample_at),
        disks: diskstats,
        nets: netdev,
    };

    let report = AgentReport {
        machine_id: machine_id.to_string(),
        hostname: first_label(families, "windows_os_hostname", "hostname")
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        agent_version: VERSION.to_string(),
        collected_at: now,
        system: ReportSystem {
            os: first_label(families, "windows_os_info", "product").unwrap_or_default(),
            kernel: first_label(families, "windows_os_info", "version").unwrap_or_default(),
            arch: std::env::consts::ARCH.to_string(),
            uptime_secs: sample_value(families, "windows_os_uptime").max(0.0) as u64,
        },
        cpu: ReportCpu {
            usage_pct,
            cores: count_cores(families),
            // Windows 无 loadavg 概念，恒为 0
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        },
        memory,
        disks,
        nets,
        // Windows 暂无传感器采集器
        sensors: Vec::new(),
        processes: sample_value(families, "windows_system_processes").max(0.0) as u32,
    };
    (report, basis)
}

/// 清理续期临时文件（失败仅记录调试日志，不影响主流程）
fn cleanup_temp(tmp: &Path) {
    if let Err(error) = std::fs::remove_file(tmp) {
        tracing::debug!(%error, path = %tmp.display(), "清理续期临时文件失败");
    }
}

/// 在目标文件同目录写 `.new` 临时文件（无 chmod：Windows 文件继承目录 ACL）
fn write_temp_file(path: &Path, data: &[u8]) -> std::io::Result<PathBuf> {
    let tmp = PathBuf::from(format!("{}.new", path.display()));
    std::fs::write(&tmp, data)?;
    Ok(tmp)
}

/// 续期产物落盘：证书与私钥先全部写为同目录 `.new` 临时文件，写全后依次
/// rename 原子替换。临时文件阶段任一步失败即清理并报错，旧物料保持不变；
/// rename 阶段失败同样清理未完成项（同目录 rename 在写入成功后几乎不可能
/// 失败，跨文件瞬时窗口可忽略）。
///
/// 产物有效性（证书可解析、私钥含 PEM 头）已由 core 在调用前校验，
/// 本函数只负责平台落盘语义。
fn write_renewed_material(
    cert_dir: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), ReporterError> {
    let cert_path = cert_dir.join("client.pem");
    let key_path = cert_dir.join("client.key");

    let cert_tmp = write_temp_file(&cert_path, cert_pem.as_bytes())?;
    let key_tmp = match write_temp_file(&key_path, key_pem.as_bytes()) {
        Ok(tmp) => tmp,
        Err(error) => {
            cleanup_temp(&cert_tmp);
            return Err(ReporterError::Io(error));
        }
    };
    if let Err(error) = std::fs::rename(&cert_tmp, &cert_path) {
        cleanup_temp(&cert_tmp);
        cleanup_temp(&key_tmp);
        return Err(ReporterError::Io(error));
    }
    if let Err(error) = std::fs::rename(&key_tmp, &key_path) {
        cleanup_temp(&key_tmp);
        return Err(ReporterError::Io(error));
    }
    Ok(())
}

/// 机器标识：windows 读注册表 MachineGuid，缺失/读取失败回退内存随机
/// uuid v4（不落盘：生产环境注册表可读性恒成立，回退仅出现在异常环境）
fn resolve_machine_id() -> String {
    #[cfg(target_os = "windows")]
    match crate::ffi::machine_guid() {
        Ok(guid) if !guid.trim().is_empty() => return guid.trim().to_string(),
        Ok(_) => {
            tracing::warn!("注册表 MachineGuid 为空，回退内存随机机器标识（重启会变化）");
        }
        Err(error) => {
            tracing::warn!(%error, "读取注册表 MachineGuid 失败，回退内存随机机器标识（重启会变化）");
        }
    }
    uuid::Uuid::new_v4().simple().to_string()
}

/// Windows 平台实现：机器标识（构造时解析一次，进程生命周期内不变）、
/// 采集一帧报告（含 200ms CPU 差分窗口）、续期产物落盘。
pub struct WindowsPlatform {
    machine_id: String,
    /// 上轮 logical_disk/net 计数器基准
    prev: Option<DiffBasis>,
}

impl WindowsPlatform {
    /// 生产构造：按默认来源解析机器标识
    pub fn new() -> Self {
        Self {
            machine_id: resolve_machine_id(),
            prev: None,
        }
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for WindowsPlatform {
    fn version(&self) -> String {
        VERSION.to_string()
    }

    fn machine_id(&self) -> String {
        self.machine_id.clone()
    }

    /// 同步采集一帧报告（阻塞：两次全量 scrape + 200ms CPU 差分窗口）。
    /// 失败时保持差分基准不变（与 Linux 平台语义一致）。
    fn collect_frame(&mut self) -> Result<AgentReport, ReporterError> {
        let collectors = default_collectors(None);
        // CPU 使用率需要 200ms 内的两个累计值差分：首次 scrape 仅作差分
        // 起点，报告数据取第二次 scrape
        let cpu_start = cpu_sample_from_families(&scrape(&collectors, &crate::SCRAPE_METRICS));
        std::thread::sleep(CPU_SAMPLE_WINDOW);
        let sample_at = Instant::now();
        let families = scrape(&collectors, &crate::SCRAPE_METRICS);

        // CPU 起点缺失（采集器故障）按 0 使用率上报，不让整帧失败
        let usage_pct = cpu_start
            .and_then(|start| {
                cpu_sample_from_families(&families).map(|end| cpu_usage_pct(&start, &end))
            })
            .unwrap_or(0.0);

        let (report, basis) = build_report(
            &self.machine_id,
            self.prev.take(),
            &families,
            sample_at,
            usage_pct,
        );
        self.prev = Some(basis);
        Ok(report)
    }

    fn persist_renewed_material(
        &self,
        cert_dir: &Path,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), ReporterError> {
        write_renewed_material(cert_dir, cert_pem, key_pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foims_agent_core::metric::MetricType;

    /// 构造带标签样本的指标族
    fn family(name: &str, samples: &[(&[(&str, &str)], f64)]) -> MetricFamily {
        let mut family = MetricFamily::new(name, "test", MetricType::Gauge);
        for (labels, value) in samples {
            let labels = labels
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            family.push_labeled(labels, *value);
        }
        family
    }

    #[test]
    fn test_cpu_sample_and_usage_diff() {
        // core=_Total 行参与聚合，其余行忽略
        let families = vec![family(
            "windows_cpu_time_total",
            &[
                (&[("core", "0,0"), ("mode", "idle")], 100.0),
                (&[("core", "0,0"), ("mode", "user")], 30.0),
                (&[("core", "_Total"), ("mode", "idle")], 80.0),
                (&[("core", "_Total"), ("mode", "user")], 30.0),
                (&[("core", "_Total"), ("mode", "privileged")], 8.0),
                (&[("core", "_Total"), ("mode", "interrupt")], 1.0),
                (&[("core", "_Total"), ("mode", "dpc")], 1.0),
            ],
        )];
        let sample = cpu_sample_from_families(&families).unwrap_or_else(|| panic!("应有聚合样本"));
        assert_eq!(sample.total, 120.0);
        assert_eq!(sample.idle, 80.0);

        let curr = CpuSample {
            total: 220.0,
            idle: 160.0,
        };
        assert!((cpu_usage_pct(&sample, &curr) - 20.0).abs() < 1e-9);
        // 全忙
        let busy = CpuSample {
            total: 220.0,
            idle: 80.0,
        };
        assert!((cpu_usage_pct(&sample, &busy) - 100.0).abs() < 1e-9);
        // 时间倒流
        assert_eq!(cpu_usage_pct(&curr, &sample), 0.0);

        // 缺 idle 模式行时聚合失败
        let no_idle = vec![family(
            "windows_cpu_time_total",
            &[(&[("core", "_Total"), ("mode", "user")], 30.0)],
        )];
        assert!(cpu_sample_from_families(&no_idle).is_none());
    }

    #[test]
    fn test_disk_rates() {
        let prev = DiskCounters {
            reads: 100.0,
            writes: 50.0,
            idle_secs: 10.0,
        };
        let curr = DiskCounters {
            reads: 160.0,
            writes: 60.0,
            idle_secs: 16.0,
        };
        let (read_iops, write_iops, util_pct) = disk_rates(&prev, &curr, 10.0);
        assert!((read_iops - 6.0).abs() < 1e-9);
        assert!((write_iops - 1.0).abs() < 1e-9);
        // (1 - 6/10) × 100 = 40
        assert!((util_pct - 40.0).abs() < 1e-9);
        // 计数重置
        let reset = DiskCounters {
            reads: 1.0,
            writes: 1.0,
            idle_secs: 0.0,
        };
        assert_eq!(disk_rates(&curr, &reset, 10.0), (0.0, 0.0, 0.0));
        // 零间隔
        assert_eq!(disk_rates(&prev, &curr, 0.0), (0.0, 0.0, 0.0));
    }

    #[test]
    fn test_net_rates() {
        let prev = NetCounters {
            rx_bytes: 1_000.0,
            tx_bytes: 500.0,
        };
        let curr = NetCounters {
            rx_bytes: 11_000.0,
            tx_bytes: 1_500.0,
        };
        let (rx_bps, tx_bps) = net_rates(&prev, &curr, 10.0);
        assert!((rx_bps - 1_000.0).abs() < 1e-9);
        assert!((tx_bps - 100.0).abs() < 1e-9);
        // 回绕按 0
        let reset = NetCounters {
            rx_bytes: 0.0,
            tx_bytes: 0.0,
        };
        assert_eq!(net_rates(&curr, &reset, 10.0), (0.0, 0.0));
    }

    #[test]
    fn test_count_cores_excludes_total() {
        let families = vec![family(
            "windows_cpu_time_total",
            &[
                (&[("core", "0,0"), ("mode", "user")], 1.0),
                (&[("core", "0,1"), ("mode", "user")], 2.0),
                (&[("core", "_Total"), ("mode", "user")], 3.0),
                (&[("core", "0,0"), ("mode", "idle")], 4.0),
            ],
        )];
        assert_eq!(count_cores(&families), 2);
        assert_eq!(count_cores(&[]), 0);
    }

    /// build_report：容量/差分/标签映射全链路（首轮差分基准为空）
    #[test]
    fn test_build_report() {
        let families = vec![
            family(
                "windows_os_info",
                &[(
                    &[("product", "Windows 11 Pro"), ("version", "10.0.22631")],
                    1.0,
                )],
            ),
            family(
                "windows_os_hostname",
                &[(
                    &[
                        ("hostname", "DESKTOP"),
                        ("domain", "corp.local"),
                        ("fqdn", "DESKTOP.corp.local"),
                    ],
                    1.0,
                )],
            ),
            family("windows_os_uptime", &[(&[], 9_876.0)]),
            family(
                "windows_cpu_time_total",
                &[
                    (&[("core", "0,0"), ("mode", "user")], 1.0),
                    (&[("core", "0,1"), ("mode", "user")], 2.0),
                    (&[("core", "_Total"), ("mode", "user")], 3.0),
                ],
            ),
            family("windows_memory_physical_total_bytes", &[(&[], 16_000.0)]),
            family("windows_memory_available_bytes", &[(&[], 6_000.0)]),
            family("windows_memory_commit_limit_bytes", &[(&[], 20_000.0)]),
            family("windows_memory_committed_bytes", &[(&[], 5_000.0)]),
            family(
                "windows_logical_disk_size_bytes",
                &[(&[("volume", "C:")], 100.0), (&[("volume", "D:")], 200.0)],
            ),
            family(
                "windows_logical_disk_free_bytes",
                &[(&[("volume", "C:")], 25.0), (&[("volume", "D:")], 40.0)],
            ),
            family(
                "windows_logical_disk_info",
                &[(&[("volume", "C:"), ("volume_name", "System")], 1.0)],
            ),
            family(
                "windows_logical_disk_reads_total",
                &[(&[("volume", "C:")], 100.0), (&[("volume", "D:")], 10.0)],
            ),
            family(
                "windows_logical_disk_writes_total",
                &[(&[("volume", "C:")], 50.0), (&[("volume", "D:")], 0.0)],
            ),
            family(
                "windows_logical_disk_idle_seconds_total",
                &[(&[("volume", "C:")], 8.0), (&[("volume", "D:")], 0.0)],
            ),
            family(
                "windows_net_bytes_received_total",
                &[(&[("nic", "Ethernet")], 1_000.0)],
            ),
            family(
                "windows_net_bytes_sent_total",
                &[(&[("nic", "Ethernet")], 500.0)],
            ),
            family(
                "windows_net_packets_received_errors_total",
                &[(&[("nic", "Ethernet")], 3.0)],
            ),
            family(
                "windows_net_packets_outbound_errors_total",
                &[(&[("nic", "Ethernet")], 4.0)],
            ),
            family("windows_system_processes", &[(&[], 142.0)]),
        ];

        let sample_at = Instant::now();
        let (report, basis) = build_report("machine", None, &families, sample_at, 42.5);

        assert_eq!(report.machine_id, "machine");
        assert_eq!(report.hostname, "DESKTOP");
        assert_eq!(report.system.os, "Windows 11 Pro");
        assert_eq!(report.system.kernel, "10.0.22631");
        assert_eq!(report.system.uptime_secs, 9_876);
        assert_eq!(report.cpu.usage_pct, 42.5);
        // mode=user 剔除 _Total 后为 2 核
        assert_eq!(report.cpu.cores, 2);
        assert_eq!(
            (report.cpu.load1, report.cpu.load5, report.cpu.load15),
            (0.0, 0.0, 0.0)
        );
        assert_eq!(report.memory.total, 16_000);
        assert_eq!(report.memory.used, 10_000);
        assert_eq!(report.memory.swap_total, 20_000);
        assert_eq!(report.memory.swap_used, 5_000);
        // 首轮差分为空：IOPS/util 记 0
        assert_eq!(report.disks.len(), 2);
        assert_eq!(report.disks[0].device, "C:");
        assert_eq!(report.disks[0].mount, "System");
        assert_eq!(report.disks[0].total, 100);
        assert_eq!(report.disks[0].used, 75);
        assert_eq!(
            (
                report.disks[0].read_iops,
                report.disks[0].write_iops,
                report.disks[0].util_pct
            ),
            (0.0, 0.0, 0.0)
        );
        assert_eq!(report.nets.len(), 1);
        assert_eq!(report.nets[0].iface, "Ethernet");
        assert_eq!(report.nets[0].errors, 7);
        assert_eq!(report.processes, 142);
        assert!(report.sensors.is_empty());
        assert!(!report.collected_at.is_empty());

        // 差分基准已记录两卷两接口
        assert_eq!(basis.disks.len(), 2);
        assert_eq!(basis.nets.len(), 1);

        // 第二帧差分：reads +60/10s → 6 IOPS，idle +2/10s → util 80%
        let mut second = families.clone();
        for entry in second.iter_mut() {
            if entry.name == "windows_logical_disk_reads_total" {
                entry.samples[0].value = 160.0;
            }
            if entry.name == "windows_logical_disk_idle_seconds_total" {
                entry.samples[0].value = 10.0;
            }
        }
        let later = sample_at + Duration::from_secs(10);
        let (report2, _) = build_report("machine", Some(basis), &second, later, 0.0);
        let disk_c = &report2.disks[0];
        assert!((disk_c.read_iops - 6.0).abs() < 1e-9);
        assert!((disk_c.util_pct - 80.0).abs() < 1e-9);
    }

    #[test]
    fn test_write_renewed_material() {
        let dir = std::env::temp_dir().join(format!(
            "foims-agent-windows-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("建临时目录失败: {e}"));

        let cert1 = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n";
        let key1 = "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----\n";
        write_renewed_material(&dir, cert1, key1).unwrap_or_else(|e| panic!("首次落盘失败: {e}"));
        let cert = std::fs::read_to_string(dir.join("client.pem"))
            .unwrap_or_else(|e| panic!("读取证书失败: {e}"));
        assert_eq!(cert, cert1);
        let key = std::fs::read_to_string(dir.join("client.key"))
            .unwrap_or_else(|e| panic!("读取私钥失败: {e}"));
        assert_eq!(key, key1);

        // 再次落盘应整体替换
        let cert2 = cert1.replace('A', "B");
        let key2 = key1.replace('A', "B");
        write_renewed_material(&dir, &cert2, &key2).unwrap_or_else(|e| panic!("替换落盘失败: {e}"));
        let cert = std::fs::read_to_string(dir.join("client.pem"))
            .unwrap_or_else(|e| panic!("复读证书失败: {e}"));
        assert_eq!(cert, cert2);

        // 目录内无 .new 临时文件残留
        let leftovers = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("读目录失败: {e}"))
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".new"))
            .count();
        assert_eq!(leftovers, 0, "不应有临时文件残留");

        // 目录不存在应整体失败且不产生半成品
        let missing = dir.join("no-such-subdir");
        assert!(write_renewed_material(&missing, cert1, key1).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
