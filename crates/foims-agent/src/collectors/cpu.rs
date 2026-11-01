//! cpu 采集器：/proc/stat CPU 时间统计。
//!
//! 对齐 node_exporter `cpu_linux.go`（updateStat 部分）与 `cpu_common.go` 的指标定义：
//! 解析 /proc/stat 的 cpuN 行，输出 `node_cpu_seconds_total{cpu,mode}`（8 种模式）与
//! `node_cpu_guest_seconds_total{cpu,mode}`（guest→user、guest_nice→nice，对齐默认
//! 开启的 --collector.cpu.guest 开关）；原始值单位为 USER_HZ，按 100 折算为秒
//! （对齐 procfs v0.22 的解析行为），聚合行 `cpu` 与原版一致不进入逐核输出。
//!
//! demo 批次移植范围：仅 /proc/stat 部分。cpu_linux.go 其余指标（cpu_info、
//! frequency_hertz、flag_info、bug_info、isolated、online，以及基于
//! thermal_throttle 的 node_cpu_core_throttles_total / node_cpu_package_throttles_total）
//! 暂未移植；原版还会跨采集缓存上次读数以平滑热插拔导致的计数回跳
//! （jumpBackSeconds），本实现为无状态版本，直接输出本次读数。

use std::collections::BTreeMap;
use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const STAT_FILE: &str = "stat";
/// 内核 CPU 时间以 USER_HZ 为单位（procfs 固定按 100 折算为秒）
const USER_HZ: f64 = 100.0;

pub struct CpuCollector {
    proc_path: PathBuf,
}

impl CpuCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for CpuCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// /proc/stat 单个 cpuN 行的各模式 CPU 时间（已折算为秒）
#[derive(Debug)]
struct CpuStat {
    user: f64,
    nice: f64,
    system: f64,
    idle: f64,
    iowait: f64,
    irq: f64,
    softirq: f64,
    steal: f64,
    guest: f64,
    guest_nice: f64,
}

/// 解析 /proc/stat：提取全部 cpuN 行，返回按 cpu 编号升序的列表。
/// 字段不足补 0（对齐 Go Sscanf 的 EOF 容忍语义）；字段非法或 cpu 编号非法时报错。
fn parse_stat(text: &str) -> Result<Vec<(u32, CpuStat)>, CollectorError> {
    let mut cpus: BTreeMap<u32, CpuStat> = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        let Some(id_text) = key.strip_prefix("cpu") else {
            continue;
        };
        // 聚合行 "cpu"：procfs 存入 CPUTotal，node_exporter 不导出，这里同样跳过
        if id_text.is_empty() {
            continue;
        }
        let id: u32 = id_text.parse().map_err(|error| CollectorError::Parse {
            file: STAT_FILE,
            reason: format!("cpu 编号非法: {key}: {error}"),
        })?;

        let mut values = [0.0_f64; 10];
        for (index, field) in fields.take(10).enumerate() {
            values[index] = field
                .parse::<f64>()
                .map_err(|error| CollectorError::Parse {
                    file: STAT_FILE,
                    reason: format!("{key} 第 {} 个字段值非法: {error}", index + 1),
                })?;
        }
        // 原始单位为 USER_HZ，折算为秒
        for value in &mut values {
            *value /= USER_HZ;
        }
        let stat = CpuStat {
            user: values[0],
            nice: values[1],
            system: values[2],
            idle: values[3],
            iowait: values[4],
            irq: values[5],
            softirq: values[6],
            steal: values[7],
            guest: values[8],
            guest_nice: values[9],
        };
        cpus.insert(id, stat);
    }
    Ok(cpus.into_iter().collect())
}

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(STAT_FILE))?;
        let cpus = parse_stat(&text)?;
        if cpus.is_empty() {
            return Err(CollectorError::NoData);
        }

        let mut seconds = MetricFamily::new(
            "node_cpu_seconds_total",
            "Seconds the CPUs spent in each mode.",
            MetricType::Counter,
        );
        let mut guest_seconds = MetricFamily::new(
            "node_cpu_guest_seconds_total",
            "Seconds the CPUs spent in guests (VMs) for each mode.",
            MetricType::Counter,
        );

        for (id, stat) in cpus {
            let cpu = id.to_string();
            // 八种模式与原版导出顺序一致
            for (mode, value) in [
                ("user", stat.user),
                ("nice", stat.nice),
                ("system", stat.system),
                ("idle", stat.idle),
                ("iowait", stat.iowait),
                ("irq", stat.irq),
                ("softirq", stat.softirq),
                ("steal", stat.steal),
            ] {
                let labels = vec![
                    ("cpu".to_string(), cpu.clone()),
                    ("mode".to_string(), mode.to_string()),
                ];
                seconds.push_labeled(labels, value);
            }
            // guest 时间已计入 user/nice，按原版拆出独立指标（默认开启）
            for (mode, value) in [("user", stat.guest), ("nice", stat.guest_nice)] {
                let labels = vec![
                    ("cpu".to_string(), cpu.clone()),
                    ("mode".to_string(), mode.to_string()),
                ];
                guest_seconds.push_labeled(labels, value);
            }
        }

        Ok(vec![seconds, guest_seconds])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = CpuCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);

        // node_cpu_seconds_total：8 核 × 8 模式
        let seconds = families
            .iter()
            .find(|f| f.name == "node_cpu_seconds_total")
            .unwrap_or_else(|| panic!("缺少 node_cpu_seconds_total"));
        assert_eq!(seconds.mtype, MetricType::Counter);
        assert_eq!(seconds.help, "Seconds the CPUs spent in each mode.");
        assert_eq!(seconds.samples.len(), 64);
        let first = &seconds.samples[0];
        assert_eq!(first.labels[0], ("cpu".to_string(), "0".to_string()));
        assert_eq!(first.labels[1], ("mode".to_string(), "user".to_string()));
        // fixture: cpu0 user=44490，按 USER_HZ=100 折算
        assert_eq!(first.value, 444.9);
        // fixture: cpu0 idle=1087069
        assert_eq!(seconds.samples[3].value, 10870.69);
        // fixture: cpu3 user=47054
        assert_eq!(seconds.samples[24].value, 470.54);
        // fixture: cpu0 softirq=3410
        assert_eq!(seconds.samples[6].value, 34.1);

        // node_cpu_guest_seconds_total：8 核 × 2 模式（user/nice）
        let guest = families
            .iter()
            .find(|f| f.name == "node_cpu_guest_seconds_total")
            .unwrap_or_else(|| panic!("缺少 node_cpu_guest_seconds_total"));
        assert_eq!(guest.mtype, MetricType::Counter);
        assert_eq!(
            guest.help,
            "Seconds the CPUs spent in guests (VMs) for each mode."
        );
        assert_eq!(guest.samples.len(), 16);
        assert_eq!(guest.samples[0].labels[0].1, "0");
        assert_eq!(guest.samples[0].labels[1].1, "user");
        // fixture: cpu0 guest=2
        assert_eq!(guest.samples[0].value, 0.02);
        assert_eq!(guest.samples[1].labels[1].1, "nice");
        // fixture: cpu0 guest_nice=1
        assert_eq!(guest.samples[1].value, 0.01);
    }

    #[test]
    fn test_parse_stat_rejects_bad_content() {
        // 非 cpu 前缀的行被忽略
        let empty = parse_stat("intr 123\nctxt 456").unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(empty.is_empty());
        // 聚合行 "cpu" 不进入逐核输出
        let only_aggregate = parse_stat("cpu 100 100 100 100 100 100 100 100 100 100")
            .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(only_aggregate.is_empty());
        // 字段值非法时报错
        assert!(matches!(
            parse_stat("cpu0 abc def"),
            Err(CollectorError::Parse { .. })
        ));
        // cpu 编号非法时报错
        assert!(matches!(
            parse_stat("cpuxyz 1 2 3 4 5 6 7 8 9 10"),
            Err(CollectorError::Parse { .. })
        ));
        // 空输入无逐核数据
        let empty = parse_stat("").unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert!(empty.is_empty());
    }
}
