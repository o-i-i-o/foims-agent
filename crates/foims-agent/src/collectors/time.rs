//! time 采集器：系统时间与时钟源。
//!
//! 对齐 node_exporter `time.go` + `time_linux.go`
//! （`registerCollector("time", defaultEnabled)`，默认启用）。输出：
//! - `node_time_seconds`：Gauge，Unix 时间秒（含纳秒小数，对齐 Go 的
//!   UnixNano()/1e9），时间取自 std::time::SystemTime；
//! - `node_time_clocksource_available_info` / `node_time_clocksource_current_info`：
//!   Gauge 恒 1，标签 device/clocksource，读 <sys>/devices/system/clocksource/*
//!   （device 标签为目录排序后的序号，对齐 Go 的 strconv.Itoa(i)）。
//!
//! 偏离：Go 源还输出 `node_time_zone_offset_seconds`（本地时区偏移），但 std 无
//! 本地时区 API 且本 crate 禁止新增依赖，故未移植。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const CLOCKSOURCE_DIR: &str = "devices/system/clocksource";
const AVAILABLE_FILE: &str = "available_clocksource";
const CURRENT_FILE: &str = "current_clocksource";

pub struct TimeCollector {
    sys_path: PathBuf,
}

impl TimeCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for TimeCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个时钟源设备信息（对齐 procfs sysfs 的 ClockSource）
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClockSource {
    available: Vec<String>,
    current: String,
}

/// 纯函数：available/current 文件文本 → 时钟源
/// （available 按空白切分为候选列表，current 取整行去首尾空白）
fn parse_clocksource(available_text: &str, current_text: &str) -> ClockSource {
    ClockSource {
        available: available_text
            .split_whitespace()
            .map(String::from)
            .collect(),
        current: current_text.trim().to_string(),
    }
}

/// 遍历 <sys>/devices/system/clocksource 下的设备并产出 clocksource 指标族；
/// 目录不存在时返回空列表（对齐 Go glob 无匹配不报错的语义）
fn clocksource_metrics(sys_path: &Path) -> Result<Vec<MetricFamily>, CollectorError> {
    let entries = match std::fs::read_dir(sys_path.join(CLOCKSOURCE_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error.into()),
    };
    // 只保留 clocksource* 设备目录（对齐 procfs 的 Glob "devices/system/clocksource/clocksource*"）
    let mut devices: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("clocksource"))
        })
        .collect();
    devices.sort();

    let mut available_family = MetricFamily::new(
        "node_time_clocksource_available_info",
        "Available clocksources read from '/sys/devices/system/clocksource'.",
        MetricType::Gauge,
    );
    let mut current_family = MetricFamily::new(
        "node_time_clocksource_current_info",
        "Current clocksource read from '/sys/devices/system/clocksource'.",
        MetricType::Gauge,
    );
    for (index, device) in devices.iter().enumerate() {
        let available_text = std::fs::read_to_string(device.join(AVAILABLE_FILE))?;
        let current_text = std::fs::read_to_string(device.join(CURRENT_FILE))?;
        let source = parse_clocksource(&available_text, &current_text);
        let device_label = index.to_string();
        for clocksource in &source.available {
            available_family.push_labeled(
                vec![
                    ("device".to_string(), device_label.clone()),
                    ("clocksource".to_string(), clocksource.clone()),
                ],
                1.0,
            );
        }
        current_family.push_labeled(
            vec![
                ("device".to_string(), device_label.clone()),
                ("clocksource".to_string(), source.current),
            ],
            1.0,
        );
    }

    let mut out = Vec::new();
    if !available_family.samples.is_empty() {
        out.push(available_family);
    }
    if !current_family.samples.is_empty() {
        out.push(current_family);
    }
    Ok(out)
}

impl Collector for TimeCollector {
    fn name(&self) -> &'static str {
        "time"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut out = Vec::new();

        // node_time_seconds：纳秒精度换算为秒，与 Go 的 UnixNano()/1e9 一致
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CollectorError::Parse {
                file: "time",
                reason: format!("系统时间早于 Unix 纪元: {error}"),
            })?;
        let mut seconds = MetricFamily::new(
            "node_time_seconds",
            "System time in seconds since epoch (1970).",
            MetricType::Gauge,
        );
        seconds.push(now.as_secs_f64());
        out.push(seconds);

        out.extend(clocksource_metrics(&self.sys_path)?);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_time_seconds() {
        let collector = TimeCollector::new();
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let seconds = families
            .iter()
            .find(|f| f.name == "node_time_seconds")
            .unwrap_or_else(|| panic!("缺少 node_time_seconds"));
        assert_eq!(seconds.mtype, MetricType::Gauge);
        assert!(seconds.samples[0].value > 1e9, "时间值应大于 1e9");
    }

    #[test]
    fn test_parse_clocksource() {
        let source = parse_clocksource("tsc hpet acpi_pm\n", "tsc\n");
        assert_eq!(
            source.available,
            vec!["tsc".to_string(), "hpet".to_string(), "acpi_pm".to_string()]
        );
        assert_eq!(source.current, "tsc");
    }

    #[test]
    fn test_clocksource_metrics_synthetic() {
        // 用临时目录构造 /sys 时钟源布局，验证 device 序号标签与指标名
        let root = std::env::temp_dir().join(format!("foims-time-test-{}", std::process::id()));
        let device_dir = root.join(CLOCKSOURCE_DIR).join("clocksource0");
        std::fs::create_dir_all(&device_dir).unwrap_or_else(|e| panic!("建目录失败: {e}"));
        std::fs::write(device_dir.join(AVAILABLE_FILE), "tsc hpet\n")
            .unwrap_or_else(|e| panic!("写文件失败: {e}"));
        std::fs::write(device_dir.join(CURRENT_FILE), "tsc\n")
            .unwrap_or_else(|e| panic!("写文件失败: {e}"));

        let families = clocksource_metrics(&root).unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].name, "node_time_clocksource_available_info");
        assert_eq!(families[0].samples.len(), 2);
        assert_eq!(
            families[0].samples[0].labels,
            vec![
                ("device".to_string(), "0".to_string()),
                ("clocksource".to_string(), "tsc".to_string()),
            ]
        );
        assert_eq!(families[1].name, "node_time_clocksource_current_info");
        assert_eq!(families[1].samples[0].value, 1.0);
        assert_eq!(
            families[1].samples[0].labels[1],
            ("clocksource".to_string(), "tsc".to_string())
        );

        std::fs::remove_dir_all(&root).unwrap_or_else(|e| panic!("清理临时目录失败: {e}"));
    }

    #[test]
    fn test_clocksource_missing_dir_is_empty() {
        let families = clocksource_metrics(Path::new("/nonexistent-foims-test"))
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }
}
