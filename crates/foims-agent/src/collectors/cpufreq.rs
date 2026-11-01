//! cpufreq 采集器：CPU 频率。
//!
//! 对齐 node_exporter `cpufreq_linux.go` + `cpufreq_common.go`：遍历
//! /sys/devices/system/cpu/cpuN/cpufreq，输出 7 个频率指标与 governor 状态指标；
//! 文件值为 kHz，按 ×1000 换算为基准单位 Hz。默认使用 node_cpu_ 前缀
//! （--collector.cpufreq.enable-cpufreq-prefix 默认关闭），指标名/标签/help 与
//! Go 源逐字一致。
//!
//! demo 批次移植范围：仅 cpufreq_linux.go Update() 实际使用的
//! cpuinfo_cur/avg/min/max_freq、scaling_cur/min/max_freq、scaling_governor 与
//! scaling_available_governors；procfs 亦会解析 transition_latency/driver/
//! related_cpus/setspeed/stats 等文件，但 node_exporter 未使用，故不读取。
//!
//! 与原版的偏离（demo 简化）：缺失或无权限的指标文件按"跳过该指标"处理
//! （原版对数值文件一致，对 governor 字符串文件缺失会整体报错）；未实现原版
//! 按 /sys/devices/system/cpu/offline 过滤离线核心的逻辑；找不到任何 cpuN
//! 目录时返回 NoData（对齐原版 "could not find any cpufreq files" 报错语义）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const CPUFREQ_FILE: &str = "cpufreq";
const SYS_CPUS_DIR: &str = "devices/system/cpu";
/// sysfs cpufreq 文件单位为 kHz，换算为基准单位 Hz
const KHZ_TO_HZ: f64 = 1000.0;

pub struct CpufreqCollector {
    sys_path: PathBuf,
}

impl CpufreqCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for CpufreqCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个核心读取到的 cpufreq 数据（None 表示文件缺失/无权限，跳过对应指标）
#[derive(Debug)]
struct CpufreqStat {
    cpuinfo_cur: Option<u64>,
    cpuinfo_avg: Option<u64>,
    cpuinfo_min: Option<u64>,
    cpuinfo_max: Option<u64>,
    scaling_cur: Option<u64>,
    scaling_min: Option<u64>,
    scaling_max: Option<u64>,
    governor: Option<String>,
    available_governors: Vec<String>,
}

/// 缺失/无权限类 IO 错误：对齐原版对数值文件的跳过语义
fn is_skippable_error(error: &std::io::Error) -> bool {
    let kind = error.kind();
    kind == std::io::ErrorKind::NotFound || kind == std::io::ErrorKind::PermissionDenied
}

/// 读取无符号整数文件；不存在/无权限返回 Ok(None)（对齐原版跳过语义），其余错误上抛
fn read_u64_file(path: &Path) -> Result<Option<u64>, CollectorError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let value = text
                .trim()
                .parse::<u64>()
                .map_err(|error| CollectorError::Parse {
                    file: CPUFREQ_FILE,
                    reason: format!("{} 值非法: {error}", path.display()),
                })?;
            Ok(Some(value))
        }
        Err(error) if is_skippable_error(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// 读取字符串文件（内容去首尾空白）；缺失/无权限返回 Ok(None)
fn read_string_file(path: &Path) -> Result<Option<String>, CollectorError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text.trim().to_string())),
        Err(error) if is_skippable_error(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// 读取单个核心 cpufreq 目录下的全部指标文件
fn parse_cpufreq(dir: &Path) -> Result<CpufreqStat, CollectorError> {
    Ok(CpufreqStat {
        cpuinfo_cur: read_u64_file(&dir.join("cpuinfo_cur_freq"))?,
        cpuinfo_avg: read_u64_file(&dir.join("cpuinfo_avg_freq"))?,
        cpuinfo_min: read_u64_file(&dir.join("cpuinfo_min_freq"))?,
        cpuinfo_max: read_u64_file(&dir.join("cpuinfo_max_freq"))?,
        scaling_cur: read_u64_file(&dir.join("scaling_cur_freq"))?,
        scaling_min: read_u64_file(&dir.join("scaling_min_freq"))?,
        scaling_max: read_u64_file(&dir.join("scaling_max_freq"))?,
        governor: read_string_file(&dir.join("scaling_governor"))?,
        available_governors: read_string_file(&dir.join("scaling_available_governors"))?
            .map(|text| text.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
    })
}

/// 枚举 devices/system/cpu 下的 cpuN 目录（名称为 cpu + 纯数字），返回按编号升序的
/// 列表；cpufreq 为 None 表示该核心没有 cpufreq 子目录（对齐原版 os.Stat 跳过语义）。
fn list_cpus(sys_path: &Path) -> Result<Vec<(u32, Option<PathBuf>)>, CollectorError> {
    let mut cpus: Vec<(u32, Option<PathBuf>)> = Vec::new();
    let entries = std::fs::read_dir(sys_path.join(SYS_CPUS_DIR))?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(id_text) = name.strip_prefix("cpu") else {
            continue;
        };
        // 排除 cpuidle、cpufreq 等非 cpuN 条目（对齐原版 glob 的 cpu[0-9]* 语义）
        if id_text.is_empty() || !id_text.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let id: u32 = id_text.parse().map_err(|error| CollectorError::Parse {
            file: CPUFREQ_FILE,
            reason: format!("cpu 编号非法: {name}: {error}"),
        })?;

        let cpufreq_dir = entry.path().join("cpufreq");
        let has_cpufreq = match std::fs::metadata(&cpufreq_dir) {
            Ok(meta) => meta.is_dir(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let cpufreq = has_cpufreq.then_some(cpufreq_dir);
        cpus.push((id, cpufreq));
    }
    cpus.sort_by_key(|entry| entry.0);
    Ok(cpus)
}

/// cpu 标签
fn cpu_label(cpu: &str) -> Vec<(String, String)> {
    vec![("cpu".to_string(), cpu.to_string())]
}

impl Collector for CpufreqCollector {
    fn name(&self) -> &'static str {
        "cpufreq"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let cpus = list_cpus(&self.sys_path)?;
        if cpus.is_empty() {
            // 对齐原版：找不到任何 cpuN 时报错（could not find any cpufreq files）
            return Err(CollectorError::NoData);
        }

        // 指标定义与顺序对齐 cpufreq_common.go newCPUFreqDescs / cpufreq_linux.go Update
        let mut hertz = MetricFamily::new(
            "node_cpu_frequency_hertz",
            "Current CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut avg_hertz = MetricFamily::new(
            "node_cpu_frequency_avg_hertz",
            "Average CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut min_hertz = MetricFamily::new(
            "node_cpu_frequency_min_hertz",
            "Minimum CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut max_hertz = MetricFamily::new(
            "node_cpu_frequency_max_hertz",
            "Maximum CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut scaling_hertz = MetricFamily::new(
            "node_cpu_scaling_frequency_hertz",
            "Current scaled CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut scaling_min_hertz = MetricFamily::new(
            "node_cpu_scaling_frequency_min_hertz",
            "Minimum scaled CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut scaling_max_hertz = MetricFamily::new(
            "node_cpu_scaling_frequency_max_hertz",
            "Maximum scaled CPU thread frequency in hertz.",
            MetricType::Gauge,
        );
        let mut governor = MetricFamily::new(
            "node_cpu_scaling_governor",
            "Current enabled CPU frequency governor.",
            MetricType::Gauge,
        );

        for (id, dir) in cpus {
            let Some(dir) = dir else {
                continue;
            };
            let stat = parse_cpufreq(&dir)?;
            let cpu = id.to_string();

            if let Some(value) = stat.cpuinfo_cur {
                hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.cpuinfo_avg {
                avg_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.cpuinfo_min {
                min_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.cpuinfo_max {
                max_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.scaling_cur {
                scaling_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.scaling_min {
                scaling_min_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            if let Some(value) = stat.scaling_max {
                scaling_max_hertz.push_labeled(cpu_label(&cpu), value as f64 * KHZ_TO_HZ);
            }
            // governor：对每个可用 governor 输出 0/1 状态（当前生效者为 1）
            if let Some(current) = &stat.governor {
                for name in &stat.available_governors {
                    let state = if name == current { 1.0 } else { 0.0 };
                    let labels = vec![
                        ("cpu".to_string(), cpu.clone()),
                        ("governor".to_string(), name.clone()),
                    ];
                    governor.push_labeled(labels, state);
                }
            }
        }

        Ok(vec![
            hertz,
            avg_hertz,
            min_hertz,
            max_hertz,
            scaling_hertz,
            scaling_min_hertz,
            scaling_max_hertz,
            governor,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = CpufreqCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let names: Vec<&str> = families.iter().map(|f| f.name.as_str()).collect();

        // 全部 8 个指标族（默认 node_cpu_ 前缀，与 Go 源逐字一致）
        assert!(names.contains(&"node_cpu_frequency_hertz"));
        assert!(names.contains(&"node_cpu_frequency_avg_hertz"));
        assert!(names.contains(&"node_cpu_frequency_min_hertz"));
        assert!(names.contains(&"node_cpu_frequency_max_hertz"));
        assert!(names.contains(&"node_cpu_scaling_frequency_hertz"));
        assert!(names.contains(&"node_cpu_scaling_frequency_min_hertz"));
        assert!(names.contains(&"node_cpu_scaling_frequency_max_hertz"));
        assert!(names.contains(&"node_cpu_scaling_governor"));

        // scaling_cur_freq：两个核心齐全（kHz→Hz）
        let scaling = families
            .iter()
            .find(|f| f.name == "node_cpu_scaling_frequency_hertz")
            .unwrap_or_else(|| panic!("缺少 node_cpu_scaling_frequency_hertz"));
        assert_eq!(scaling.mtype, MetricType::Gauge);
        assert_eq!(scaling.samples.len(), 2);
        assert_eq!(
            scaling.samples[0].labels[0],
            ("cpu".to_string(), "0".to_string())
        );
        assert_eq!(scaling.samples[0].value, 1_699_981_000.0);
        assert_eq!(scaling.samples[1].value, 1_799_982_000.0);

        // cpu1 缺失 cpuinfo_min_freq：node_cpu_frequency_min_hertz 仅输出 cpu0
        let min_freq = families
            .iter()
            .find(|f| f.name == "node_cpu_frequency_min_hertz")
            .unwrap_or_else(|| panic!("缺少 node_cpu_frequency_min_hertz"));
        assert_eq!(min_freq.samples.len(), 1);
        assert_eq!(min_freq.samples[0].labels[0].1, "0");
        assert_eq!(min_freq.samples[0].value, 800_000_000.0);

        // cpuinfo_max_freq 两核齐全
        let max_freq = families
            .iter()
            .find(|f| f.name == "node_cpu_frequency_max_hertz")
            .unwrap_or_else(|| panic!("缺少 node_cpu_frequency_max_hertz"));
        assert_eq!(max_freq.samples.len(), 2);
        assert_eq!(max_freq.samples[1].value, 3_800_000_000.0);

        // governor 状态：每核每个可用 governor 一行，当前生效者为 1
        let governor = families
            .iter()
            .find(|f| f.name == "node_cpu_scaling_governor")
            .unwrap_or_else(|| panic!("缺少 node_cpu_scaling_governor"));
        assert_eq!(governor.samples.len(), 4);
        let powersave_cpu1 = governor
            .samples
            .iter()
            .find(|sample| sample.labels[0].1 == "1" && sample.labels[1].1 == "powersave")
            .unwrap_or_else(|| panic!("缺少 cpu1 的 powersave 样本"));
        // cpu1 当前 governor 为 performance
        assert_eq!(powersave_cpu1.value, 0.0);
        let performance_cpu1 = governor
            .samples
            .iter()
            .find(|sample| sample.labels[0].1 == "1" && sample.labels[1].1 == "performance")
            .unwrap_or_else(|| panic!("缺少 cpu1 的 performance 样本"));
        assert_eq!(performance_cpu1.value, 1.0);
    }

    #[test]
    fn test_list_cpus_sorted_and_filtered() {
        let cpus = list_cpus(&fixture_root()).unwrap_or_else(|e| panic!("枚举失败: {e}"));
        // 按编号升序，且仅包含 cpuN 目录
        let ids: Vec<u32> = cpus.iter().map(|entry| entry.0).collect();
        assert_eq!(ids, vec![0, 1]);
        // 两个核心均有 cpufreq 子目录
        assert!(cpus.iter().all(|entry| entry.1.is_some()));
    }

    #[test]
    fn test_read_u64_file_rejects_bad_value() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        // 非数值内容报解析错误
        let error = read_u64_file(&manifest.join("Cargo.toml"))
            .err()
            .unwrap_or_else(|| panic!("非法数值应返回错误"));
        assert!(matches!(error, CollectorError::Parse { .. }));
        // 缺失文件返回 None
        let missing = read_u64_file(&manifest.join("no_such_file"))
            .unwrap_or_else(|e| panic!("读取失败: {e}"));
        assert_eq!(missing, None);
    }
}
