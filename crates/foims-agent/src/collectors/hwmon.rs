//! hwmon 采集器：硬件传感器监控（/sys/class/hwmon）。
//!
//! 对齐 node_exporter `hwmon_linux.go`，逐段移植 Update/updateHwmon/hwmonName/
//! hwmonHumanReadableChipName/collectSensorData/explodeSensorFilename 与
//! cleanMetricName：遍历 hwmon* 目录，聚合 name、in*/temp*/fan*/curr*/power*/
//! energy*/humidity* 等传感器文件与 device/ 子目录，输出 node_hwmon_* 指标族；
//! 芯片名按 device 路径 > name 文件 > hwmonX 目录名三级推导，重名时以 name
//! 文件内容或目录名消歧。
//! 移植省略项：`--collector.hwmon.chip-include/exclude` 与
//! `--collector.hwmon.sensor-include/exclude` 正则过滤（demo 阶段不支持）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 参与采集的传感器类型（逐字对齐 hwmonSensorTypes）
const SENSOR_TYPES: [&str; 14] = [
    "vrm",
    "beep_enable",
    "update_interval",
    "in",
    "cpu",
    "fan",
    "pwm",
    "temp",
    "curr",
    "power",
    "energy",
    "humidity",
    "intrusion",
    "freq",
];

/// 单芯片传感器数据：sensor 键（如 temp1）→ 属性（input/label 等，空串表示
/// 文件名本身无 `_属性` 后缀，对齐 Go map[string]map[string]string）
type SensorData = BTreeMap<String, BTreeMap<String, String>>;

pub struct HwmonCollector {
    sys_path: PathBuf,
}

impl HwmonCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for HwmonCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 名称清洗（对齐 cleanMetricName：转小写、非 [a-z0-9:_] 替换为下划线、去首尾下划线）
fn clean_metric_name(name: &str) -> String {
    let replaced: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == ':' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    replaced.trim_matches('_').to_string()
}

/// 拆分传感器文件名 `<type><num>[_<property>]`。
///
/// 对齐正则 `^([^0-9]+)([0-9]*)?(_(.+))?$` 的贪婪 + 回溯语义：type 取最长非
/// ASCII 数字前缀；id 段长度从最长向 0 枚举回溯；property 需以 `_` 开头且
/// 至少一个字符（`.` 不匹配换行）。返回 (类型, 编号, 属性)，编号缺省记 0。
fn explode_sensor_filename(filename: &str) -> Option<(&str, i64, &str)> {
    let bytes = filename.as_bytes();
    // type 段：起始于头的最长非 ASCII 数字前缀
    let type_end = bytes
        .iter()
        .position(|byte| byte.is_ascii_digit())
        .unwrap_or(bytes.len());
    if type_end == 0 {
        return None;
    }
    let (sensor_type, rest) = filename.split_at(type_end);
    // id 段长度从最长向 0 枚举，模拟正则贪婪匹配失败后的回溯
    let digit_end = rest
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(rest.len());
    for id_len in (0..=digit_end).rev() {
        let remainder = &rest[id_len..];
        let property = if remainder.is_empty() {
            Some("")
        } else if let Some(property) = remainder.strip_prefix('_') {
            // property 组 (.+)：至少一个字符且不含换行
            (!property.is_empty() && !property.contains('\n')).then_some(property)
        } else {
            None
        };
        if let Some(property) = property {
            // 编号缺省记 0；超出 i64 范围视为不匹配（对齐 strconv.Atoi ErrRange）
            let sensor_num = if id_len == 0 {
                0
            } else {
                rest[..id_len].parse::<i64>().ok()?
            };
            return Some((sensor_type, sensor_num, property));
        }
    }
    None
}

/// 读传感器值文件（对齐 sysReadFile：单次读取、截断 128 字节、去首尾换行；
/// 读取失败返回 None 由调用方静默跳过，对齐 addValueFile 直接 return）
fn read_value_file(path: &Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let truncated = &raw[..raw.len().min(128)];
    // 无效 UTF-8 字节以替换字符呈现（对齐 strings.ToValidUTF8 的效果）
    let text = String::from_utf8_lossy(truncated);
    Some(text.trim_matches('\n').to_string())
}

/// 读取目录下全部传感器文件到 data（对齐 collectSensorData + addValueFile）
fn collect_sensor_data(dir: &Path, data: &mut SensorData) -> Result<(), CollectorError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        let Some((sensor_type, sensor_num, property)) = explode_sensor_filename(filename) else {
            continue;
        };
        if !SENSOR_TYPES.contains(&sensor_type) {
            continue;
        }
        // sensor 键 = 类型 + 编号（编号缺省记 0，对齐 Go Itoa 拼接）
        let sensor_key = format!("{sensor_type}{sensor_num}");
        if let Some(value) = read_value_file(&entry.path()) {
            data.entry(sensor_key)
                .or_default()
                .insert(property.to_string(), value);
        }
    }
    Ok(())
}

/// 推导芯片名（对齐 hwmonName：device 路径 > name 文件 > hwmonX 目录名）。
///
/// sensor 编号随内核模块加载顺序变化，而 device 物理路径稳定，故优先使用。
fn hwmon_name(dir: &Path) -> Result<String, CollectorError> {
    // 偏好 1：device 符号链接解析出的物理设备路径（总是唯一）
    if let Ok(device_path) = std::fs::canonicalize(dir.join("device")) {
        // 末段为设备名，倒数第二段为总线类型（如 platform/coretemp.0）
        if let Some(dev_name) = device_path.file_name().and_then(|name| name.to_str()) {
            let clean_dev_name = clean_metric_name(dev_name);
            let clean_dev_type = device_path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                .map(clean_metric_name)
                .unwrap_or_default();
            if !clean_dev_type.is_empty() && !clean_dev_name.is_empty() {
                return Ok(format!("{clean_dev_type}_{clean_dev_name}"));
            }
            if !clean_dev_name.is_empty() {
                return Ok(clean_dev_name);
            }
        }
    }

    // 偏好 2：name 文件内容（人可读名，如 bat0 / coretemp）
    if let Ok(raw) = std::fs::read(dir.join("name"))
        && !raw.is_empty()
    {
        let clean = clean_metric_name(&String::from_utf8_lossy(&raw));
        if !clean.is_empty() {
            return Ok(clean);
        }
    }

    // 兜底：真实路径末段（hwmonX）
    let real_dir = std::fs::canonicalize(dir)?;
    let clean = real_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(clean_metric_name)
        .unwrap_or_default();
    if clean.is_empty() {
        return Err(CollectorError::Parse {
            file: "class/hwmon",
            reason: format!("无法为 {} 推导芯片名", dir.display()),
        });
    }
    Ok(clean)
}

/// 人可读芯片名（对齐 hwmonHumanReadableChipName：仅认 name 文件，允许重名）
fn hwmon_human_readable_chip_name(dir: &Path) -> Option<String> {
    let raw = std::fs::read(dir.join("name")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let clean = clean_metric_name(&String::from_utf8_lossy(&raw));
    if clean.is_empty() {
        return None;
    }
    Some(clean)
}

/// 取或创建同名指标族（Go 中同名指标的 help/type 恒定，首个定义即唯一）
fn get_or_create_family<'a>(
    families: &'a mut Vec<MetricFamily>,
    name: &str,
    help: &str,
    mtype: MetricType,
) -> &'a mut MetricFamily {
    if let Some(index) = families.iter().position(|family| family.name == name) {
        return &mut families[index];
    }
    families.push(MetricFamily::new(name, help, mtype));
    let last = families.len() - 1;
    &mut families[last]
}

/// 采集单个芯片目录（对齐 updateHwmon）
fn update_hwmon(
    dir: &Path,
    chip_name: &str,
    families: &mut Vec<MetricFamily>,
) -> Result<(), CollectorError> {
    let mut data = SensorData::new();
    collect_sensor_data(dir, &mut data)?;
    // device/ 子目录存在时其传感器文件并入同一数据集（同名属性覆盖，对齐 os.Stat 判断）
    let device_dir = dir.join("device");
    if device_dir.exists() {
        collect_sensor_data(&device_dir, &mut data)?;
    }

    // 芯片元数据注解：name 文件可读时输出 chip_name
    if let Some(readable_name) = hwmon_human_readable_chip_name(dir) {
        get_or_create_family(
            families,
            "node_hwmon_chip_names",
            "Annotation metric for human-readable chip names",
            MetricType::Gauge,
        )
        .push_labeled(
            vec![
                ("chip".to_string(), chip_name.to_string()),
                ("chip_name".to_string(), readable_name),
            ],
            1.0,
        );
    }

    for (sensor, sensor_data) in &data {
        // sensor 键由 explode_sensor_filename 生成，此处必然可解析
        let Some((sensor_type, ..)) = explode_sensor_filename(sensor) else {
            continue;
        };
        let labels = vec![
            ("chip".to_string(), chip_name.to_string()),
            ("sensor".to_string(), sensor.clone()),
        ];

        // label 文件 → 注解指标（无效 UTF-8 已在读文件时替换，对齐 ToValidUTF8）
        if let Some(label_text) = sensor_data.get("label") {
            get_or_create_family(
                families,
                "node_hwmon_sensor_label",
                "Label for given chip and sensor",
                MetricType::Gauge,
            )
            .push_labeled(
                vec![
                    ("chip".to_string(), chip_name.to_string()),
                    ("sensor".to_string(), sensor.clone()),
                    ("label".to_string(), label_text.clone()),
                ],
                1.0,
            );
        }

        if sensor_type == "beep_enable" {
            let value = if sensor_data.get("").map(String::as_str) == Some("1") {
                1.0
            } else {
                0.0
            };
            get_or_create_family(
                families,
                "node_hwmon_beep_enabled",
                "Hardware beep enabled",
                MetricType::Gauge,
            )
            .push_labeled(labels.clone(), value);
            continue;
        }
        if sensor_type == "vrm" {
            let Some(value) = sensor_data.get("").and_then(|raw| raw.parse::<f64>().ok()) else {
                // 解析失败跳过整个传感器（对齐 Go continue 语义）
                continue;
            };
            get_or_create_family(
                families,
                "node_hwmon_voltage_regulator_version",
                "Hardware voltage regulator",
                MetricType::Gauge,
            )
            .push_labeled(labels.clone(), value);
            continue;
        }
        if sensor_type == "update_interval" {
            let Some(value) = sensor_data.get("").and_then(|raw| raw.parse::<f64>().ok()) else {
                continue;
            };
            get_or_create_family(
                families,
                "node_hwmon_update_interval_seconds",
                "Hardware monitor update interval",
                MetricType::Gauge,
            )
            .push_labeled(labels.clone(), value * 0.001);
            continue;
        }

        let prefix = format!("node_hwmon_{sensor_type}");
        for (element, raw_value) in sensor_data {
            if element == "label" {
                continue;
            }
            let mut name = prefix.clone();
            if element == "input" {
                // input 即数值本身；仅当同传感器还存在空属性文件时才追加后缀
                if sensor_data.contains_key("") {
                    name.push_str("_input");
                }
            } else if !element.is_empty() {
                name.push('_');
                name.push_str(&clean_metric_name(element));
            }
            let Ok(parsed_value) = raw_value.parse::<f64>() else {
                continue;
            };

            // fault/alarm/beep 为状态量，输出不带单位
            if element == "fault" || element == "alarm" {
                get_or_create_family(
                    families,
                    &name,
                    &format!("Hardware sensor {element} status ({sensor_type})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value);
                continue;
            }
            if element == "beep" {
                get_or_create_family(
                    families,
                    &format!("{name}_enabled"),
                    "Hardware monitor sensor has beeping enabled",
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value);
                continue;
            }

            // 以下按传感器类型换算单位
            if sensor_type == "in" || sensor_type == "cpu" {
                get_or_create_family(
                    families,
                    &format!("{name}_volts"),
                    &format!("Hardware monitor for voltage ({element})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value * 0.001);
                continue;
            }
            if sensor_type == "temp" && element != "type" {
                // help 文本中空属性以 input 呈现
                let shown = if element.is_empty() {
                    "input"
                } else {
                    element.as_str()
                };
                get_or_create_family(
                    families,
                    &format!("{name}_celsius"),
                    &format!("Hardware monitor for temperature ({shown})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value * 0.001);
                continue;
            }
            if sensor_type == "curr" {
                get_or_create_family(
                    families,
                    &format!("{name}_amps"),
                    &format!("Hardware monitor for current ({element})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value * 0.001);
                continue;
            }
            if sensor_type == "energy" {
                get_or_create_family(
                    families,
                    &format!("{name}_joule_total"),
                    &format!("Hardware monitor for joules used so far ({element})"),
                    MetricType::Counter,
                )
                .push_labeled(labels.clone(), parsed_value / 1_000_000.0);
                continue;
            }
            if sensor_type == "power" && element == "accuracy" {
                get_or_create_family(
                    families,
                    &name,
                    "Hardware monitor power meter accuracy, as a ratio",
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value / 1_000_000.0);
                continue;
            }
            if sensor_type == "power"
                && matches!(
                    element.as_str(),
                    "average_interval" | "average_interval_min" | "average_interval_max"
                )
            {
                get_or_create_family(
                    families,
                    &format!("{name}_seconds"),
                    &format!("Hardware monitor power usage update interval ({element})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value * 0.001);
                continue;
            }
            if sensor_type == "power" {
                get_or_create_family(
                    families,
                    &format!("{name}_watt"),
                    &format!("Hardware monitor for power usage in watts ({element})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value / 1_000_000.0);
                continue;
            }
            if sensor_type == "humidity" {
                get_or_create_family(
                    families,
                    &name,
                    &format!(
                        "Hardware monitor for humidity, as a ratio (multiply with 100.0 to get the humidity as a percentage) ({element})"
                    ),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value / 1_000_000.0);
                continue;
            }
            if sensor_type == "fan"
                && matches!(element.as_str(), "input" | "min" | "max" | "target")
            {
                get_or_create_family(
                    families,
                    &format!("{name}_rpm"),
                    &format!("Hardware monitor for fan revolutions per minute ({element})"),
                    MetricType::Gauge,
                )
                .push_labeled(labels.clone(), parsed_value);
                continue;
            }
            if sensor_type == "freq" && element == "input" {
                if let Some(label) = sensor_data.get("label") {
                    // freq 指标的 sensor 标签替换为清洗后的 label 内容
                    get_or_create_family(
                        families,
                        &format!("{name}_freq_mhz"),
                        "Hardware monitor for GPU frequency in MHz",
                        MetricType::Gauge,
                    )
                    .push_labeled(
                        vec![
                            ("chip".to_string(), chip_name.to_string()),
                            ("sensor".to_string(), clean_metric_name(label)),
                        ],
                        parsed_value / 1_000_000.0,
                    );
                }
                continue;
            }
            // 兜底：原值直出
            get_or_create_family(
                families,
                &name,
                &format!("Hardware monitor {sensor_type} element {element}"),
                MetricType::Gauge,
            )
            .push_labeled(labels.clone(), parsed_value);
        }
    }
    Ok(())
}

impl Collector for HwmonCollector {
    fn name(&self) -> &'static str {
        "hwmon"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        // 对齐 sysFilePath("class")/hwmon
        let hwmon_root = self.sys_path.join("class").join("hwmon");
        let dir_entries = match std::fs::read_dir(&hwmon_root) {
            Ok(entries) => entries,
            // 系统无 hwmon 不视为错误（对齐 os.ErrNotExist → ErrNoData）
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };

        /// Pass 1 收集的芯片条目（对齐 Go 局部结构 hwmonEntry）
        struct HwmonEntry {
            dir: PathBuf,
            base_name: String,
            name_file: String,
        }

        // Pass 1：枚举 hwmon 目录并预计算基础芯片名，统计重名用于 Pass 2 消歧
        // （多个 hwmon 节点可能共享同一父设备，如 asus-nb-wmi 的风扇/传感器双节点）
        let mut entries: Vec<HwmonEntry> = Vec::new();
        let mut chip_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut name_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
        for entry in dir_entries {
            let dir = entry?.path();
            // hwmon* 在 sysfs 中通常是符号链接：先 Lstat，是链接则跟进目标
            let Ok(metadata) = std::fs::symlink_metadata(&dir) else {
                continue;
            };
            let metadata = if metadata.file_type().is_symlink() {
                let Ok(target) = std::fs::metadata(&dir) else {
                    continue;
                };
                target
            } else {
                metadata
            };
            if !metadata.is_dir() {
                continue;
            }
            let Ok(base_name) = hwmon_name(&dir) else {
                continue;
            };
            // name 文件内容（TrimSpace），读取失败视为空
            let name_file = std::fs::read(dir.join("name"))
                .map(|raw| String::from_utf8_lossy(&raw).trim().to_string())
                .unwrap_or_default();

            *chip_counts.entry(base_name.clone()).or_insert(0) += 1;
            *name_counts
                .entry((base_name.clone(), name_file.clone()))
                .or_insert(0) += 1;
            entries.push(HwmonEntry {
                dir,
                base_name,
                name_file,
            });
        }

        // Pass 2：消歧出唯一 chip 名后逐芯片采集；错误只记最后一个（对齐 lastErr）
        let mut families: Vec<MetricFamily> = Vec::new();
        let mut last_error: Option<CollectorError> = None;
        for entry in &entries {
            let mut chip_name = entry.base_name.clone();
            if chip_counts.get(&entry.base_name).copied().unwrap_or(0) > 1 {
                let mut suffix = clean_metric_name(&entry.name_file);
                if suffix.is_empty()
                    || name_counts
                        .get(&(entry.base_name.clone(), entry.name_file.clone()))
                        .copied()
                        .unwrap_or(0)
                        > 1
                {
                    // name 文件内容无法消歧时回退 hwmonX 目录名
                    let base = entry
                        .dir
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("");
                    suffix = clean_metric_name(base);
                }
                chip_name = format!("{chip_name}_{suffix}");
            }

            if let Err(error) = update_hwmon(&entry.dir, &chip_name, &mut families) {
                last_error = Some(error);
            }
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(families),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foims_agent_core::metric::Sample;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    /// 按指标名与完整标签集精确定位样本
    fn find_sample<'a>(
        families: &'a [MetricFamily],
        name: &str,
        labels: &[(&str, &str)],
    ) -> Option<&'a Sample> {
        families
            .iter()
            .find(|family| family.name == name)
            .and_then(|family| {
                family.samples.iter().find(|sample| {
                    sample.labels.len() == labels.len()
                        && sample.labels.iter().all(|(key, value)| {
                            labels.iter().any(|(want_key, want_value)| {
                                key == want_key && value == want_value
                            })
                        })
                })
            })
    }

    #[test]
    fn test_metric_families_and_labels() {
        let collector = HwmonCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|error| panic!("采集失败: {error}"));
        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();

        assert!(names.contains(&"node_hwmon_chip_names"));
        assert!(names.contains(&"node_hwmon_sensor_label"));
        assert!(names.contains(&"node_hwmon_temp_celsius"));
        assert!(names.contains(&"node_hwmon_fan_rpm"));
        assert!(names.contains(&"node_hwmon_in_volts"));

        // chip 注解：name 文件内容同时决定 chip 与 chip_name
        let coretemp = find_sample(
            &families,
            "node_hwmon_chip_names",
            &[("chip", "coretemp"), ("chip_name", "coretemp")],
        )
        .unwrap_or_else(|| panic!("缺少 coretemp 的 chip_names 样本"));
        assert_eq!(coretemp.value, 1.0);
        assert!(
            find_sample(
                &families,
                "node_hwmon_chip_names",
                &[("chip", "acpitz"), ("chip_name", "acpitz")]
            )
            .is_some(),
            "缺少 acpitz 的 chip_names 样本"
        );

        // label 文件 → sensor_label 注解
        assert!(
            find_sample(
                &families,
                "node_hwmon_sensor_label",
                &[
                    ("chip", "coretemp"),
                    ("sensor", "temp1"),
                    ("label", "Core 0")
                ]
            )
            .is_some()
        );
        assert!(
            find_sample(
                &families,
                "node_hwmon_sensor_label",
                &[
                    ("chip", "coretemp"),
                    ("sensor", "temp2"),
                    ("label", "Core 1")
                ]
            )
            .is_some()
        );

        // acpitz 缺 label 文件：不产生 sensor_label 样本（回退默认标签逻辑）
        let acpitz_label_count = families
            .iter()
            .find(|family| family.name == "node_hwmon_sensor_label")
            .unwrap_or_else(|| panic!("缺少 node_hwmon_sensor_label"))
            .samples
            .iter()
            .filter(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(key, value)| key == "chip" && value == "acpitz")
            })
            .count();
        assert_eq!(acpitz_label_count, 0);
    }

    #[test]
    fn test_sample_values() {
        let collector = HwmonCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|error| panic!("采集失败: {error}"));

        // temp1_input=45000 → 45 ℃
        let temp1 = find_sample(
            &families,
            "node_hwmon_temp_celsius",
            &[("chip", "coretemp"), ("sensor", "temp1")],
        )
        .unwrap_or_else(|| panic!("缺少 coretemp temp1 温度样本"));
        assert_eq!(temp1.value, 45.0);
        assert_eq!(temp1.labels.len(), 2);

        // temp2_input=47000 → 47 ℃
        assert_eq!(
            find_sample(
                &families,
                "node_hwmon_temp_celsius",
                &[("chip", "coretemp"), ("sensor", "temp2")]
            )
            .unwrap_or_else(|| panic!("缺少 coretemp temp2 温度样本"))
            .value,
            47.0
        );

        // acpitz 缺 label 时仍输出温度（chip 名来自 name 文件）
        assert_eq!(
            find_sample(
                &families,
                "node_hwmon_temp_celsius",
                &[("chip", "acpitz"), ("sensor", "temp1")]
            )
            .unwrap_or_else(|| panic!("缺少 acpitz temp1 温度样本"))
            .value,
            32.0
        );

        // in0_input=1150000 毫单位 → 1150.0 volts
        assert_eq!(
            find_sample(
                &families,
                "node_hwmon_in_volts",
                &[("chip", "coretemp"), ("sensor", "in0")]
            )
            .unwrap_or_else(|| panic!("缺少 coretemp in0 电压样本"))
            .value,
            1150.0
        );

        // fan1_input=2100 → 2100 rpm（fan 指标不做换算）
        assert_eq!(
            find_sample(
                &families,
                "node_hwmon_fan_rpm",
                &[("chip", "coretemp"), ("sensor", "fan1")]
            )
            .unwrap_or_else(|| panic!("缺少 coretemp fan1 风扇样本"))
            .value,
            2100.0
        );
    }

    #[test]
    fn test_temp_family_shape() {
        let collector = HwmonCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|error| panic!("采集失败: {error}"));

        let temp_family = families
            .iter()
            .find(|family| family.name == "node_hwmon_temp_celsius")
            .unwrap_or_else(|| panic!("缺少 node_hwmon_temp_celsius"));
        assert_eq!(temp_family.mtype, MetricType::Gauge);
        assert_eq!(temp_family.help, "Hardware monitor for temperature (input)");
        assert_eq!(temp_family.samples.len(), 3);
    }

    #[test]
    fn test_explode_sensor_filename() {
        assert_eq!(
            explode_sensor_filename("temp1_input"),
            Some(("temp", 1, "input"))
        );
        assert_eq!(explode_sensor_filename("temp1"), Some(("temp", 1, "")));
        assert_eq!(explode_sensor_filename("temp"), Some(("temp", 0, "")));
        // 纯非数字文件名整体作为类型
        assert_eq!(
            explode_sensor_filename("power_average_interval"),
            Some(("power_average_interval", 0, ""))
        );
        // 数字段后接非法尾巴：正则回溯失败，整体不匹配
        assert_eq!(explode_sensor_filename("temp1x"), None);
        // 数字开头不匹配 type 段
        assert_eq!(explode_sensor_filename("0foo"), None);
    }

    #[test]
    fn test_clean_metric_name() {
        assert_eq!(clean_metric_name("Core 0"), "core_0");
        assert_eq!(clean_metric_name("coretemp.0"), "coretemp_0");
        assert_eq!(clean_metric_name("__foo__"), "foo");
    }
}
