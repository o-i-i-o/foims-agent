//! thermal_zone 采集器：热区温度。
//!
//! 对齐 node_exporter `thermal_zone_linux.go`：遍历 `/sys/class/thermal/thermal_zone*`
//! 读取 temp/type，输出 `node_thermal_zone_temp`（Gauge，值为 temp/1000 的摄氏度），
//! help 逐字取自 Go 源；标签 `{type,zone}`（原版标签顺序为 `{zone,type}`）。
//! 原版同时输出的 `node_cooling_device_{cur_state,max_state}` 不在本次移植范围。
//! 差异：单个热区 temp/type 读不到时跳过该热区（原版任一字段出错即整体返回
//! ErrNoData）；`/sys/class/thermal` 目录缺失或不可读时返回 NoData（对齐原版）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 热区目录（相对 sys_path）
const CLASS_THERMAL_DIR: &str = "class/thermal";

/// 热区目录名前缀
const ZONE_PREFIX: &str = "thermal_zone";

pub struct ThermalZoneCollector {
    sys_path: PathBuf,
}

impl ThermalZoneCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for ThermalZoneCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个热区的读取结果
struct ZoneReading {
    /// 热区序号（thermal_zoneN 的 N，对齐 procfs 的 stats.Name）
    zone: String,
    /// type 文件内容（trim 后，作为标签值）
    ztype: String,
    /// temp 文件的原始值（毫摄氏度）
    temp_milli: i64,
}

/// 读取单个热区的 temp 与 type；任一字段缺失或非法时返回 None
/// （按任务规格跳过该热区）
fn read_zone(class_dir: &Path, zone_name: &str) -> Option<ZoneReading> {
    let zone_dir = class_dir.join(zone_name);
    let temp_text = std::fs::read_to_string(zone_dir.join("temp")).ok()?;
    let temp_milli = temp_text.trim().parse::<i64>().ok()?;
    let ztype = std::fs::read_to_string(zone_dir.join("type"))
        .ok()?
        .trim()
        .to_string();
    let zone = zone_name
        .strip_prefix(ZONE_PREFIX)
        .unwrap_or(zone_name)
        .to_string();
    Some(ZoneReading {
        zone,
        ztype,
        temp_milli,
    })
}

impl Collector for ThermalZoneCollector {
    fn name(&self) -> &'static str {
        "thermal_zone"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let class_dir = self.sys_path.join(CLASS_THERMAL_DIR);
        // 目录缺失/不可读 → NoData（对齐原版 os.ErrNotExist/ErrPermission → ErrNoData）
        let entries = match std::fs::read_dir(&class_dir) {
            Ok(entries) => entries,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(CollectorError::Io(error)),
        };

        // 收集并按名称排序 thermal_zone*（对齐 glob 的字典序，保证输出稳定）
        let mut zone_names: Vec<String> = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.starts_with(ZONE_PREFIX) {
                zone_names.push(name);
            }
        }
        zone_names.sort();

        let mut family = MetricFamily::new(
            "node_thermal_zone_temp",
            "Zone temperature in Celsius",
            MetricType::Gauge,
        );
        for name in &zone_names {
            let Some(reading) = read_zone(&class_dir, name) else {
                // temp/type 读不到 → 跳过该热区
                tracing::debug!(zone = %name, "热区字段缺失，跳过");
                continue;
            };
            family.push_labeled(
                vec![
                    ("type".to_string(), reading.ztype),
                    ("zone".to_string(), reading.zone),
                ],
                reading.temp_milli as f64 / 1000.0,
            );
        }
        Ok(vec![family])
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
        let collector = ThermalZoneCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));

        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_thermal_zone_temp");
        assert_eq!(families[0].mtype, MetricType::Gauge);
        // thermal_zone1 缺 type → 跳过，仅 zone0 输出
        assert_eq!(families[0].samples.len(), 1);
        assert_eq!(
            families[0].samples[0].labels,
            vec![
                ("type".to_string(), "acpitz".to_string()),
                ("zone".to_string(), "0".to_string())
            ]
        );
        // 45500 毫摄氏度 → 45.5 摄氏度
        assert_eq!(families[0].samples[0].value, 45.5);
    }

    #[test]
    fn test_collect_nodata_when_sys_missing() {
        let collector = ThermalZoneCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
