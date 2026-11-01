//! watchdog 采集器：硬件看门狗状态。
//!
//! 对齐 node_exporter `watchdog.go`（默认启用）：遍历 /sys/class/watchdog/
//! watchdog<N> 目录，输出（标签 name = 目录名）：
//! - 数值指标（Gauge；对应文件缺失或非数值时跳过，对齐 procfs 的 nil 处理）：
//!
//!   `node_watchdog_{bootstatus,fw_version,nowayout,timeleft_seconds,
//!   timeout_seconds,pretimeout_seconds,access_cs0}`；
//! - `node_watchdog_info{name,options,identity,state,status,pretimeout_governor}`
//!
//!   （Gauge 恒 1；字符串文件缺失时标签为空字符串，指标始终输出）。
//!
//! watchdog 目录缺失或不可读时返回 NoData。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// watchdog 类目录（相对 sys_path）
const WATCHDOG_DIR: &str = "class/watchdog";

pub struct WatchdogCollector {
    sys_path: PathBuf,
}

impl WatchdogCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for WatchdogCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取数值属性文件（缺失或非数值返回 None）
fn read_u64(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse::<u64>().ok()
}

/// 读取字符串属性文件（缺失返回 None；内容 trim）
fn read_string(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
}

impl Collector for WatchdogCollector {
    fn name(&self) -> &'static str {
        "watchdog"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let watchdog_dir = self.sys_path.join(WATCHDOG_DIR);
        let mut device_dirs: Vec<PathBuf> = match std::fs::read_dir(&watchdog_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                // 跳过点文件：sysfs 真实设备名均为 watchdog<N>，无点前缀形态；
                // fixture 用 .gitkeep 占位保留「空属性设备」目录（git 不跟踪空目录）
                .filter(|path| {
                    !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with('.'))
                })
                .filter(|path| path.is_dir())
                .collect(),
            // 目录缺失（无看门狗设备）→ NoData（对齐 Go）
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };
        device_dirs.sort();

        let mut bootstatus = MetricFamily::new(
            "node_watchdog_bootstatus",
            "Value of /sys/class/watchdog/<watchdog>/bootstatus",
            MetricType::Gauge,
        );
        let mut fw_version = MetricFamily::new(
            "node_watchdog_fw_version",
            "Value of /sys/class/watchdog/<watchdog>/fw_version",
            MetricType::Gauge,
        );
        let mut nowayout = MetricFamily::new(
            "node_watchdog_nowayout",
            "Value of /sys/class/watchdog/<watchdog>/nowayout",
            MetricType::Gauge,
        );
        let mut timeleft = MetricFamily::new(
            "node_watchdog_timeleft_seconds",
            "Value of /sys/class/watchdog/<watchdog>/timeleft",
            MetricType::Gauge,
        );
        let mut timeout = MetricFamily::new(
            "node_watchdog_timeout_seconds",
            "Value of /sys/class/watchdog/<watchdog>/timeout",
            MetricType::Gauge,
        );
        let mut pretimeout = MetricFamily::new(
            "node_watchdog_pretimeout_seconds",
            "Value of /sys/class/watchdog/<watchdog>/pretimeout",
            MetricType::Gauge,
        );
        let mut access_cs0 = MetricFamily::new(
            "node_watchdog_access_cs0",
            "Value of /sys/class/watchdog/<watchdog>/access_cs0",
            MetricType::Gauge,
        );
        let mut info = MetricFamily::new(
            "node_watchdog_info",
            "Info of /sys/class/watchdog/<watchdog>",
            MetricType::Gauge,
        );

        for dir in device_dirs {
            let Some(name) = dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let name_label = vec![("name".to_string(), name.to_string())];
            let push_u64 = |family: &mut MetricFamily, file: &str, label: &[(String, String)]| {
                if let Some(value) = read_u64(&dir.join(file)) {
                    family.push_labeled(label.to_vec(), value as f64);
                }
            };
            push_u64(&mut bootstatus, "bootstatus", &name_label);
            push_u64(&mut fw_version, "fw_version", &name_label);
            push_u64(&mut nowayout, "nowayout", &name_label);
            push_u64(&mut timeleft, "timeleft", &name_label);
            push_u64(&mut timeout, "timeout", &name_label);
            push_u64(&mut pretimeout, "pretimeout", &name_label);
            push_u64(&mut access_cs0, "access_cs0", &name_label);

            // info 指标始终输出；字符串属性缺失时空字符串
            let label_value = |file: &str| read_string(&dir.join(file)).unwrap_or_default();
            let mut labels = name_label;
            labels.push(("options".to_string(), label_value("options")));
            labels.push(("identity".to_string(), label_value("identity")));
            labels.push(("state".to_string(), label_value("state")));
            labels.push(("status".to_string(), label_value("status")));
            labels.push((
                "pretimeout_governor".to_string(),
                label_value("pretimeout_governor"),
            ));
            info.push_labeled(labels, 1.0);
        }

        Ok(vec![
            bootstatus, fw_version, nowayout, timeleft, timeout, pretimeout, access_cs0, info,
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
        let collector = WatchdogCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 8);
        assert_eq!(families[0].name, "node_watchdog_bootstatus");
        assert_eq!(families[0].mtype, MetricType::Gauge);
        let value = |name: usize| -> f64 { families[name].samples[0].value };
        // fixture watchdog0 数值
        assert_eq!(value(0), 1.0); // bootstatus
        assert_eq!(value(1), 2.0); // fw_version
        assert_eq!(value(2), 0.0); // nowayout
        assert_eq!(value(3), 300.0); // timeleft
        assert_eq!(value(4), 60.0); // timeout
        assert_eq!(value(5), 120.0); // pretimeout
        assert_eq!(value(6), 0.0); // access_cs0
        // info：字符串属性作为标签；watchdog1 为空目录，仅输出空标签 info
        let info = &families[7];
        assert_eq!(info.name, "node_watchdog_info");
        assert_eq!(info.samples.len(), 2);
        let info0 = info
            .samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(k, v)| k == "name" && v == "watchdog0")
            })
            .unwrap_or_else(|| panic!("缺少 watchdog0 的 info 样本"));
        let get = |sample_labels: &[(String, String)], key: &str| -> String {
            sample_labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get(&info0.labels, "identity"), "Software Watchdog");
        assert_eq!(get(&info0.labels, "options"), "0x8380");
        assert_eq!(get(&info0.labels, "state"), "active");
        assert_eq!(get(&info0.labels, "status"), "0x8000");
        assert_eq!(get(&info0.labels, "pretimeout_governor"), "noop");
        // watchdog1 无属性文件 → 标签全为空字符串
        let info1 = &info.samples[1];
        assert!(
            info1
                .labels
                .iter()
                .all(|(k, v)| k == "name" || v.is_empty())
        );
    }

    #[test]
    fn test_missing_watchdog_dir_is_nodata() {
        let collector = WatchdogCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
