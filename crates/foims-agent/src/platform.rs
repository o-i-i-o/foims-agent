//! Linux 平台实现：机器标识、指标采集与报告组装、续期产物落盘。
//!
//! 实现 [`Platform`] 三件事，上报循环与其余传输逻辑全部复用
//! `foims_agent_core::reporter::Reporter`：
//! - 机器标识：`/etc/machine-id` → `/var/lib/dbus/machine-id` → 本地持久化
//!   文件（uuid v4，目录 0755 / 文件 0644，无写盘权限时回退内存随机值并告警）；
//! - 采集：`default_collectors` 抓取 node_* 指标，diskstats/netdev 累计
//!   计数器差分为 IOPS 与 bps，差分状态保存在本结构内；
//! - 续期落盘：证书 0644 / 私钥 0600，临时文件 + rename 原子替换。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use foims_agent_core::collector::scrape;
use foims_agent_core::metric::{MetricFamily, Sample};
use foims_agent_core::reporter::{Platform, ReporterError};
use foims_protocol::report::{
    AgentReport, ReportCpu, ReportDisk, ReportMemory, ReportNet, ReportSensor, ReportSystem,
};

use crate::VERSION;
use crate::default_collectors;

/// CPU 使用率两次采样窗口
const CPU_SAMPLE_WINDOW: Duration = Duration::from_millis(200);

/// machine-id 三个候选路径（抽出来便于测试注入临时目录）
#[derive(Debug, Clone)]
pub struct MachineIdPaths {
    /// /etc/machine-id（优先）
    pub etc_machine_id: PathBuf,
    /// /var/lib/dbus/machine-id（回退）
    pub dbus_machine_id: PathBuf,
    /// agent 本地持久化文件（前两者都缺失时生成 uuid v4 写入）
    pub local_file: PathBuf,
}

impl MachineIdPaths {
    /// 生产路径
    pub fn production() -> Self {
        Self {
            etc_machine_id: PathBuf::from("/etc/machine-id"),
            dbus_machine_id: PathBuf::from("/var/lib/dbus/machine-id"),
            local_file: PathBuf::from("/var/lib/foims-agent/machine-id"),
        }
    }
}

/// 解析机器标识：trim + 小写；三处都拿不到时生成 uuid v4 并尝试持久化，
/// 写盘失败（如无权限）则回退内存随机值并告警（每次进程启动会变化）。
pub fn resolve_machine_id(paths: &MachineIdPaths) -> String {
    let candidates = [
        &paths.etc_machine_id,
        &paths.dbus_machine_id,
        &paths.local_file,
    ];
    for candidate in candidates {
        let Ok(text) = std::fs::read_to_string(candidate) else {
            continue;
        };
        let cleaned = text.trim().to_lowercase();
        if !cleaned.is_empty() {
            return cleaned;
        }
    }
    // 生成 uuid v4（simple 格式 32 位小写十六进制，与 machine-id 惯例一致）
    let generated = uuid::Uuid::new_v4().simple().to_string();
    match persist_machine_id(&paths.local_file, &generated) {
        Ok(()) => tracing::info!(
            path = %paths.local_file.display(),
            "已生成并持久化 machine-id"
        ),
        Err(error) => tracing::warn!(
            %error,
            path = %paths.local_file.display(),
            "machine-id 持久化失败，本进程使用内存随机值（重启会变化）"
        ),
    }
    generated
}

/// 持久化 machine-id：父目录 0755、文件 0644
fn persist_machine_id(path: &Path, value: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let mut perms = std::fs::metadata(parent)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(parent, perms)?;
    }
    std::fs::write(path, value)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// /proc/stat 聚合行采样（原始 USER_HZ 单位，比值与单位无关）
#[derive(Debug, Clone, Copy, PartialEq)]
struct CpuSample {
    total: f64,
    idle: f64,
}

/// 解析 /proc/stat 聚合 "cpu" 行：total 为前 8 列之和，idle 取 idle + iowait。
///
/// guest/guest_nice 已计入 user/nice（内核口径），整行求和会双计虚拟机
/// 负载导致使用率虚高，因此 total 仅累加 user..steal 共 8 列。
fn parse_cpu_aggregate(text: &str) -> Option<CpuSample> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    let mut values = Vec::new();
    for field in line.split_whitespace().skip(1) {
        let value: f64 = field.parse().ok()?;
        values.push(value);
    }
    if values.len() < 4 {
        return None;
    }
    // 列序：user nice system idle iowait irq softirq steal [guest guest_nice]
    let total: f64 = values.iter().take(8).sum();
    let idle = values[3] + values.get(4).copied().unwrap_or(0.0);
    Some(CpuSample { total, idle })
}

/// 读取当前 CPU 采样
fn read_cpu_sample() -> Result<CpuSample, ReporterError> {
    let text = std::fs::read_to_string("/proc/stat")
        .map_err(|error| ReporterError::Collect(format!("读取 /proc/stat: {error}")))?;
    parse_cpu_aggregate(&text)
        .ok_or_else(|| ReporterError::Collect("/proc/stat 无聚合 cpu 行".to_string()))
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

/// diskstats 累计计数器（I/O 差分基准）
#[derive(Debug, Clone, Copy, Default)]
struct DiskCounters {
    reads: f64,
    writes: f64,
    io_time_secs: f64,
}

/// netdev 累计计数器（bps 差分基准）
#[derive(Debug, Clone, Copy, Default)]
struct NetCounters {
    rx_bytes: f64,
    tx_bytes: f64,
}

/// 上轮差分基准：diskstats/netdev 计数器 + 采样时刻
#[derive(Debug, Clone, Default)]
struct DiffBasis {
    at: Option<Instant>,
    disks: BTreeMap<String, DiskCounters>,
    nets: BTreeMap<String, NetCounters>,
}

/// diskstats 差分 → (read_iops, write_iops, util_pct)；
/// 计数回绕/重置（curr < prev）或间隔非正时按 0 处理
fn disk_rates(prev: &DiskCounters, curr: &DiskCounters, elapsed_secs: f64) -> (f64, f64, f64) {
    if elapsed_secs <= 0.0 {
        return (0.0, 0.0, 0.0);
    }
    let read_delta = curr.reads - prev.reads;
    let write_delta = curr.writes - prev.writes;
    let io_delta = curr.io_time_secs - prev.io_time_secs;
    if read_delta < 0.0 || write_delta < 0.0 || io_delta < 0.0 {
        return (0.0, 0.0, 0.0);
    }
    (
        read_delta / elapsed_secs,
        write_delta / elapsed_secs,
        (io_delta / elapsed_secs * 100.0).clamp(0.0, 100.0),
    )
}

/// netdev 差分 → (rx_bps, tx_bps)；回绕/重置按 0 处理
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
        .find(|(k, _)| k == key)
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

/// 设备标签 → 磁盘设备名（"/dev/sda1" → "sda1"；无 /dev 前缀取末段）
fn disk_device_name(device_label: &str) -> &str {
    device_label.rsplit('/').next().unwrap_or(device_label)
}

/// /proc/uptime 首字段（秒）
fn read_uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|f| f.parse::<f64>().ok())
        })
        .map(|secs| secs.max(0.0) as u64)
        .unwrap_or(0)
}

/// /proc 下数字目录计数（进程总数）
fn count_processes() -> u32 {
    let count = std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.file_name().to_str().is_some_and(|name| {
                        !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
                    })
                })
                .count()
        })
        .unwrap_or(0);
    count as u32
}

/// 主机名：uname nodename → /proc/sys/kernel/hostname → "unknown"
fn read_hostname() -> String {
    let raw = rustix::system::uname();
    let nodename = raw.nodename().to_string_lossy().trim().to_string();
    if !nodename.is_empty() {
        return nodename;
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|text| text.trim().to_string())
        .ok()
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// RFC3339 UTC 当前时刻（如 "2026-10-10T04:00:00Z"）
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 由 scrape 输出组装 AgentReport，并产出新差分基准（diskstats/netdev）
fn build_report(
    machine_id: &str,
    prev: Option<DiffBasis>,
    families: &[MetricFamily],
    sample_at: Instant,
    usage_pct: f64,
) -> (AgentReport, DiffBasis) {
    let raw = rustix::system::uname();
    let now = now_rfc3339();

    // 差分：与上轮计数器对比（首轮无基准，速率记 0）
    let prev = prev.unwrap_or_default();
    let elapsed = prev
        .at
        .map(|at| sample_at.duration_since(at).as_secs_f64())
        .unwrap_or(0.0);

    // CPU / 负载 / 内存
    let cores = count_cores(families);
    let memory = ReportMemory {
        total: sample_value(families, "node_memory_MemTotal_bytes").max(0.0) as u64,
        used: used_memory_bytes(families),
        swap_total: sample_value(families, "node_memory_SwapTotal_bytes").max(0.0) as u64,
        swap_used: (sample_value(families, "node_memory_SwapTotal_bytes")
            - sample_value(families, "node_memory_SwapFree_bytes"))
        .max(0.0) as u64,
    };

    // 磁盘：filesystem 容量 + diskstats 差分
    let diskstats = collect_disk_counters(families);
    // 首轮 elapsed 为 0，差分自动归 0，无需特判空基准
    let disks = build_disks(families, &diskstats, Some(&prev.disks), elapsed);

    // 网络：netdev 差分
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
        hostname: read_hostname(),
        agent_version: VERSION.to_string(),
        collected_at: now,
        system: ReportSystem {
            os: os_description(families, &raw),
            kernel: raw.release().to_string_lossy().into_owned(),
            arch: raw.machine().to_string_lossy().into_owned(),
            uptime_secs: read_uptime_secs(),
        },
        cpu: ReportCpu {
            usage_pct,
            cores,
            load1: sample_value(families, "node_load1"),
            load5: sample_value(families, "node_load5"),
            load15: sample_value(families, "node_load15"),
        },
        memory,
        disks,
        nets,
        sensors: collect_sensors(families),
        processes: count_processes(),
    };
    (report, basis)
}

/// 内存已用：total - available（旧内核无 MemAvailable 回退 MemFree）
fn used_memory_bytes(families: &[MetricFamily]) -> u64 {
    let total = sample_value(families, "node_memory_MemTotal_bytes");
    let available = find_family(families, "node_memory_MemAvailable_bytes")
        .and_then(|family| family.samples.first())
        .map(|sample| sample.value)
        .unwrap_or_else(|| sample_value(families, "node_memory_MemFree_bytes"));
    (total - available).max(0.0) as u64
}

/// 逻辑核心数：node_cpu_seconds_total 中 mode=user 的样本数（每核一条）
fn count_cores(families: &[MetricFamily]) -> u32 {
    find_family(families, "node_cpu_seconds_total")
        .map(|family| {
            family
                .samples
                .iter()
                .filter(|sample| label_value(sample, "mode") == Some("user"))
                .count() as u32
        })
        .unwrap_or(0)
}

/// os 描述：os-release PRETTY_NAME，缺失回退 uname sysname
fn os_description(families: &[MetricFamily], raw: &rustix::system::Uname) -> String {
    find_family(families, "node_os_info")
        .and_then(|family| family.samples.first())
        .and_then(|sample| label_value(sample, "pretty_name"))
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| raw.sysname().to_string_lossy().into_owned())
}

/// 从 diskstats 三族指标收集各设备计数器
fn collect_disk_counters(families: &[MetricFamily]) -> BTreeMap<String, DiskCounters> {
    let mut counters: BTreeMap<String, DiskCounters> = BTreeMap::new();
    let mut insert =
        |families: &[MetricFamily], name: &str, pick: fn(&mut DiskCounters) -> &mut f64| {
            if let Some(family) = find_family(families, name) {
                for sample in &family.samples {
                    if let Some(device) = label_value(sample, "device") {
                        let entry = counters.entry(device.to_string()).or_default();
                        *pick(entry) = sample.value;
                    }
                }
            }
        };
    insert(families, "node_disk_reads_completed_total", |c| {
        &mut c.reads
    });
    insert(families, "node_disk_writes_completed_total", |c| {
        &mut c.writes
    });
    insert(families, "node_disk_io_time_seconds_total", |c| {
        &mut c.io_time_secs
    });
    counters
}

/// filesystem 容量 + diskstats 差分 → ReportDisk 列表
/// （设备名映射到挂载设备；无法匹配的挂载点 IOPS/util 记 0）
fn build_disks(
    families: &[MetricFamily],
    diskstats: &BTreeMap<String, DiskCounters>,
    prev: Option<&BTreeMap<String, DiskCounters>>,
    elapsed_secs: f64,
) -> Vec<ReportDisk> {
    let Some(size_family) = find_family(families, "node_filesystem_size_bytes") else {
        return Vec::new();
    };
    let mut disks = Vec::new();
    for size_sample in &size_family.samples {
        let Some(device_label) = label_value(size_sample, "device") else {
            continue;
        };
        let Some(mount) = label_value(size_sample, "mountpoint") else {
            continue;
        };
        let total = size_sample.value.max(0.0) as u64;
        let free = find_labeled(
            families,
            "node_filesystem_free_bytes",
            &[("device", device_label), ("mountpoint", mount)],
        )
        .map(|sample| sample.value)
        .unwrap_or(0.0);
        let used = (size_sample.value - free).max(0.0) as u64;

        let device = disk_device_name(device_label).to_string();
        let (read_iops, write_iops, util_pct) = match (
            prev.and_then(|basis| basis.get(&device)),
            diskstats.get(&device),
        ) {
            (Some(prev_counters), Some(curr_counters)) => {
                disk_rates(prev_counters, curr_counters, elapsed_secs)
            }
            _ => (0.0, 0.0, 0.0),
        };
        disks.push(ReportDisk {
            device,
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

/// 从 netdev 指标收集各接口字节计数器
fn collect_net_counters(families: &[MetricFamily]) -> BTreeMap<String, NetCounters> {
    let mut counters: BTreeMap<String, NetCounters> = BTreeMap::new();
    let mut insert =
        |families: &[MetricFamily], name: &str, pick: fn(&mut NetCounters) -> &mut f64| {
            if let Some(family) = find_family(families, name) {
                for sample in &family.samples {
                    if let Some(device) = label_value(sample, "device") {
                        let entry = counters.entry(device.to_string()).or_default();
                        *pick(entry) = sample.value;
                    }
                }
            }
        };
    insert(families, "node_network_receive_bytes_total", |c| {
        &mut c.rx_bytes
    });
    insert(families, "node_network_transmit_bytes_total", |c| {
        &mut c.tx_bytes
    });
    counters
}

/// netdev 字节差分 → ReportNet 列表（首轮无基准 bps 记 0，errors 取累计值）
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
            (receive_errors(families, iface) + transmit_errors(families, iface)).max(0.0) as u64;
        nets.push(ReportNet {
            iface: iface.clone(),
            rx_bps,
            tx_bps,
            errors,
        });
    }
    nets
}

/// 单接口累计接收错误数
fn receive_errors(families: &[MetricFamily], iface: &str) -> f64 {
    find_labeled(
        families,
        "node_network_receive_errs_total",
        &[("device", iface)],
    )
    .map(|sample| sample.value)
    .unwrap_or(0.0)
}

/// 单接口累计发送错误数
fn transmit_errors(families: &[MetricFamily], iface: &str) -> f64 {
    find_labeled(
        families,
        "node_network_transmit_errs_total",
        &[("device", iface)],
    )
    .map(|sample| sample.value)
    .unwrap_or(0.0)
}

/// 传感器列表：hwmon 温度（采集器已折算 ℃）与风扇（RPM）、thermal 热区（℃）；
/// 标签沿用采集器逻辑：hwmon 用 chip + sensor_label（无则 sensor 键），
/// 热区用 type + zone
fn collect_sensors(families: &[MetricFamily]) -> Vec<ReportSensor> {
    let mut sensors = Vec::new();
    let mut push_hwmon = |name: &str, kind: &'static str| {
        let Some(family) = find_family(families, name) else {
            return;
        };
        for sample in &family.samples {
            let Some(chip) = label_value(sample, "chip") else {
                continue;
            };
            let Some(sensor) = label_value(sample, "sensor") else {
                continue;
            };
            let label_text = find_labeled(
                families,
                "node_hwmon_sensor_label",
                &[("chip", chip), ("sensor", sensor)],
            )
            .and_then(|labeled| label_value(labeled, "label"))
            .unwrap_or(sensor);
            sensors.push(ReportSensor {
                label: format!("{chip} {label_text}"),
                kind: kind.to_string(),
                value: sample.value,
            });
        }
    };
    push_hwmon("node_hwmon_temp_celsius", "temp");
    push_hwmon("node_hwmon_fan_input", "fan");

    // thermal 热区温度（node_thermal_zone_temp 值已是摄氏度）
    if let Some(family) = find_family(families, "node_thermal_zone_temp") {
        for sample in &family.samples {
            let ztype = label_value(sample, "type").unwrap_or("thermal");
            let zone = label_value(sample, "zone").unwrap_or("");
            sensors.push(ReportSensor {
                label: format!("{ztype} {zone}"),
                kind: "temp".to_string(),
                value: sample.value,
            });
        }
    }
    sensors
}

/// 清理续期临时文件（失败仅记录调试日志，不影响主流程）
fn cleanup_temp(tmp: &Path) {
    if let Err(error) = std::fs::remove_file(tmp) {
        tracing::debug!(%error, path = %tmp.display(), "清理续期临时文件失败");
    }
}

/// 在目标文件同目录写临时文件并设定权限（供原子替换使用）
fn write_temp_file(path: &Path, data: &[u8], mode: u32) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = PathBuf::from(format!("{}.new", path.display()));
    std::fs::write(&tmp, data)?;
    if let Err(error) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)) {
        cleanup_temp(&tmp);
        return Err(error);
    }
    Ok(tmp)
}

/// 续期产物落盘：证书与私钥先全部写为同目录 `.new` 临时文件（证书 0644 /
/// 私钥 0600），写全后依次 rename 原子替换。临时文件阶段任一步失败即清理
/// 并报错，旧物料保持不变；rename 阶段失败同样清理未完成项（同目录 rename
/// 在写入成功后几乎不可能失败，跨文件瞬时窗口可忽略）。
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

    let cert_tmp = write_temp_file(&cert_path, cert_pem.as_bytes(), 0o644)?;
    let key_tmp = match write_temp_file(&key_path, key_pem.as_bytes(), 0o600) {
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

/// Linux 平台实现：机器标识（构造时解析一次，进程生命周期内不变）、
/// 采集一帧报告（含 200ms CPU 差分窗口）、续期产物落盘。
pub struct LinuxPlatform {
    machine_id: String,
    /// 上轮 diskstats/netdev 计数器基准
    prev: Option<DiffBasis>,
}

impl LinuxPlatform {
    /// 生产构造：按默认路径解析机器标识
    pub fn new() -> Self {
        Self::with_paths(MachineIdPaths::production())
    }

    /// 指定路径构造（测试注入临时目录用）
    pub fn with_paths(paths: MachineIdPaths) -> Self {
        let machine_id = resolve_machine_id(&paths);
        Self {
            machine_id,
            prev: None,
        }
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for LinuxPlatform {
    fn version(&self) -> String {
        VERSION.to_string()
    }

    fn machine_id(&self) -> String {
        self.machine_id.clone()
    }

    /// 同步采集一帧报告（阻塞：200ms CPU 差分窗口与 /proc 阻塞读取）。
    /// 失败时保持差分基准不变（与原 collect_sync 语义一致）。
    fn collect_frame(&mut self) -> Result<AgentReport, ReporterError> {
        let cpu_start = read_cpu_sample()?;
        let sample_at = Instant::now();
        let collectors = default_collectors(None);
        let families = scrape(&collectors, &crate::SCRAPE_METRICS);
        std::thread::sleep(CPU_SAMPLE_WINDOW);
        let cpu_end = read_cpu_sample()?;

        let usage_pct = cpu_usage_pct(&cpu_start, &cpu_end);
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
    use std::io::Write;

    /// 唯一临时目录
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "foims-agent-test-{}-{}-{tag}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("建临时目录失败: {e}"));
        dir
    }

    #[test]
    fn test_resolve_machine_id_from_etc() {
        let dir = temp_dir("etc");
        let etc = dir.join("machine-id");
        let mut file = std::fs::File::create(&etc).unwrap_or_else(|e| panic!("建文件失败: {e}"));
        file.write_all(b"ABCDEF0123456789ABCDEF0123456789\n")
            .unwrap_or_else(|e| panic!("写入失败: {e}"));
        let paths = MachineIdPaths {
            etc_machine_id: etc,
            dbus_machine_id: dir.join("missing-dbus"),
            local_file: dir.join("missing-local"),
        };
        assert_eq!(
            resolve_machine_id(&paths),
            "abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn test_resolve_machine_id_dbus_fallback() {
        let dir = temp_dir("dbus");
        let dbus = dir.join("machine-id");
        std::fs::write(&dbus, "  0123456789ABCDEF0123456789ABCDEF \n")
            .unwrap_or_else(|e| panic!("写入失败: {e}"));
        let paths = MachineIdPaths {
            etc_machine_id: dir.join("missing-etc"),
            dbus_machine_id: dbus,
            local_file: dir.join("missing-local"),
        };
        assert_eq!(
            resolve_machine_id(&paths),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_resolve_machine_id_generates_local_file() {
        let dir = temp_dir("gen");
        let paths = MachineIdPaths {
            etc_machine_id: dir.join("missing-etc"),
            dbus_machine_id: dir.join("missing-dbus"),
            local_file: dir.join("state/machine-id"),
        };
        let first = resolve_machine_id(&paths);
        assert_eq!(first.len(), 32);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        // 已持久化且可复读
        let persisted =
            std::fs::read_to_string(&paths.local_file).unwrap_or_else(|e| panic!("读取失败: {e}"));
        assert_eq!(persisted.trim(), first);
        // 再次解析命中本地文件
        assert_eq!(resolve_machine_id(&paths), first);
    }

    #[test]
    fn test_resolve_machine_id_unwritable_falls_back_to_memory() {
        let dir = temp_dir("unwritable");
        // 以普通文件占位父目录路径，create_dir_all 必然失败
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").unwrap_or_else(|e| panic!("写入失败: {e}"));
        let paths = MachineIdPaths {
            etc_machine_id: dir.join("missing-etc"),
            dbus_machine_id: dir.join("missing-dbus"),
            local_file: blocker.join("machine-id"),
        };
        let id = resolve_machine_id(&paths);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // 未产生持久化文件
        assert!(std::fs::read_to_string(&paths.local_file).is_err());
    }

    #[test]
    fn test_cpu_usage_diff() {
        let prev = CpuSample {
            total: 100.0,
            idle: 80.0,
        };
        let curr = CpuSample {
            total: 200.0,
            idle: 160.0,
        };
        assert!((cpu_usage_pct(&prev, &curr) - 20.0).abs() < 1e-9);
        // 全忙
        let busy = CpuSample {
            total: 200.0,
            idle: 80.0,
        };
        assert!((cpu_usage_pct(&prev, &busy) - 100.0).abs() < 1e-9);
        // 时间倒流
        assert_eq!(cpu_usage_pct(&curr, &prev), 0.0);
    }

    #[test]
    fn test_parse_cpu_aggregate() {
        let text = "cpu  10 20 30 40 10 0 0 0 0 0\ncpu0 1 1 1 1 0 0 0 0 0 0\nintr 1\n";
        let sample = parse_cpu_aggregate(text).unwrap_or_else(|| panic!("应解析出聚合行"));
        assert!((sample.total - 110.0).abs() < 1e-9);
        assert!((sample.idle - 50.0).abs() < 1e-9);
        assert!(parse_cpu_aggregate("cpu").is_none());
        assert!(parse_cpu_aggregate("cpu a b c d").is_none());
        assert!(parse_cpu_aggregate("intr 1").is_none());
        // guest/guest_nice 已计入 user/nice：total 不得整行求和双计
        let guest = "cpu  10 20 30 40 10 0 0 0 7 9\n";
        let sample = parse_cpu_aggregate(guest).unwrap_or_else(|| panic!("应解析出聚合行"));
        assert!((sample.total - 110.0).abs() < 1e-9);
    }

    #[test]
    fn test_disk_rates() {
        let prev = DiskCounters {
            reads: 100.0,
            writes: 50.0,
            io_time_secs: 10.0,
        };
        let curr = DiskCounters {
            reads: 160.0,
            writes: 60.0,
            io_time_secs: 16.0,
        };
        let (read_iops, write_iops, util_pct) = disk_rates(&prev, &curr, 10.0);
        assert!((read_iops - 6.0).abs() < 1e-9);
        assert!((write_iops - 1.0).abs() < 1e-9);
        assert!((util_pct - 60.0).abs() < 1e-9);
        // 计数重置
        let reset = DiskCounters {
            reads: 1.0,
            writes: 1.0,
            io_time_secs: 0.0,
        };
        let (r, w, u) = disk_rates(&curr, &reset, 10.0);
        assert_eq!((r, w, u), (0.0, 0.0, 0.0));
        // 零间隔
        let (r, w, u) = disk_rates(&prev, &curr, 0.0);
        assert_eq!((r, w, u), (0.0, 0.0, 0.0));
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
    fn test_disk_device_name() {
        assert_eq!(disk_device_name("/dev/sda1"), "sda1");
        assert_eq!(disk_device_name("/dev/mapper/vg-root"), "vg-root");
        assert_eq!(disk_device_name("tmpfs"), "tmpfs");
    }

    /// 生成测试用自签证书与私钥 PEM（write_renewed_material 前置校验已由
    /// core 完成，本测试直接验证落盘语义）
    fn renewed_material() -> (String, String) {
        let pair = rcgen::generate_simple_self_signed(vec!["foims-agent-renew-test".to_string()])
            .unwrap_or_else(|e| panic!("自签失败: {e}"));
        (pair.cert.pem(), pair.signing_key.serialize_pem())
    }

    #[test]
    fn test_write_renewed_material() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("renew-material");
        let (cert1, key1) = renewed_material();
        write_renewed_material(&dir, &cert1, &key1).unwrap_or_else(|e| panic!("首次落盘失败: {e}"));
        let cert = std::fs::read_to_string(dir.join("client.pem"))
            .unwrap_or_else(|e| panic!("读取证书失败: {e}"));
        assert_eq!(cert, cert1);
        let key = std::fs::read_to_string(dir.join("client.key"))
            .unwrap_or_else(|e| panic!("读取私钥失败: {e}"));
        assert_eq!(key, key1);
        let cert_mode = std::fs::metadata(dir.join("client.pem"))
            .unwrap_or_else(|e| panic!("读证书元数据失败: {e}"))
            .permissions()
            .mode();
        assert_eq!(cert_mode & 0o777, 0o644, "证书应为 0644");
        let key_mode = std::fs::metadata(dir.join("client.key"))
            .unwrap_or_else(|e| panic!("读私钥元数据失败: {e}"))
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o600, "私钥应为 0600");
        // 目录内无 .new 临时文件残留
        let leftovers = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("读目录失败: {e}"))
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".new"))
            .count();
        assert_eq!(leftovers, 0, "不应有临时文件残留");

        // 再次落盘应整体替换
        let (cert2, key2) = renewed_material();
        write_renewed_material(&dir, &cert2, &key2).unwrap_or_else(|e| panic!("替换落盘失败: {e}"));
        let cert = std::fs::read_to_string(dir.join("client.pem"))
            .unwrap_or_else(|e| panic!("复读证书失败: {e}"));
        assert_eq!(cert, cert2);

        // 目录不存在应整体失败且不产生半成品
        let missing = dir.join("no-such-subdir");
        let (cert3, key3) = renewed_material();
        assert!(write_renewed_material(&missing, &cert3, &key3).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
