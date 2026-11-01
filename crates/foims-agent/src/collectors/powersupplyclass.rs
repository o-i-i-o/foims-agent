//! powersupplyclass 采集器：电源供应 sysfs 信息。
//!
//! 对齐 node_exporter `powersupplyclass.go` + `powersupplyclass_linux.go`
//! （默认启用）与 procfs sysfs PowerSupplyClass（v0.23.0）：遍历
//! /sys/class/power_supply/ 全部条目，仅常规属性文件参与解析，输出
//! `node_power_supply_*` 家族（标签统一为 power_supply）：
//! - 原值 Gauge（10 个）：authentic、calibrate、capacity、
//!   capacity_alert_max、capacity_alert_min、cyclecount（cycle_count）、
//!   online、present、time_to_empty_seconds（time_to_empty_now）、
//!   time_to_full_seconds（time_to_full_now）；
//! - 微单位 Gauge（31 个，原值 ÷ 1e6）：current_boot、current_max、
//!   current_ampere（current_now）、energy_empty、energy_empty_design、
//!   energy_full、energy_full_design、energy_watthour（energy_now）、
//!   voltage_boot、voltage_max、voltage_max_design、voltage_min、
//!   voltage_min_design、voltage_volt（voltage_now）、voltage_ocv、
//!   charge_control_limit、charge_control_limit_max、charge_counter、
//!   charge_empty、charge_empty_design、charge_full、charge_full_design、
//!   charge_ampere（charge_now）、charge_term_current、
//!   constant_charge_current、constant_charge_current_max、
//!   constant_charge_voltage、constant_charge_voltage_max、
//!   precharge_current、input_current_limit、power_watt（power_now）；
//! - 温度 Gauge（8 个，原值 ÷ 10）：temp_celsius、temp_alert_max_celsius、
//!   temp_alert_min_celsius、temp_ambient_celsius、temp_ambient_max_celsius、
//!   temp_ambient_min_celsius、temp_max_celsius、temp_min_celsius；
//! - `node_power_supply_info`（Gauge，值恒 1）：power_supply 与
//!   capacity_level/charge_type/health/manufacturer/model_name/
//!   serial_number/status/technology/type/usb_type/scope 中非空的标签。
//!
//! 偏离点：
//! - 未移植 `--collector.powersupply.ignored-supplies` 正则过滤 CLI 参数；
//! - class/power_supply 目录缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - 电源按目录名字典序输出（Go map 遍历无序，仅为输出稳定性）；
//! - info 标签按 Go 源 map 字面量的声明序输出（Go map 遍历无序）；
//! - 非 UTF-8 属性值在读取时以 U+FFFD 替换（Go 侧为输出前
//!   strings.ToValidUTF8，结果一致）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 电源供应目录（相对 sys_path）
const POWER_SUPPLY_DIR: &str = "class/power_supply";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;

pub struct PowerSupplyClassCollector {
    sys_path: PathBuf,
}

impl PowerSupplyClassCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for PowerSupplyClassCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个电源的 sysfs 解析结果（对齐 procfs PowerSupply 中采集器实际输出的
/// 字段；charge_avg/current_avg/energy_avg/power_avg/voltage_avg/
/// time_to_empty_avg/time_to_full_avg 这 7 个字段 Go 侧解析但采集器不输出，
/// 此处仅校验数值合法性不保存）
#[derive(Debug, Default)]
struct PowerSupply {
    // 原值组（10 个，对齐 Go Update 第一张 map 的推送序）
    authentic: Option<i64>,
    calibrate: Option<i64>,
    capacity: Option<i64>,
    capacity_alert_max: Option<i64>,
    capacity_alert_min: Option<i64>,
    cycle_count: Option<i64>,
    online: Option<i64>,
    present: Option<i64>,
    time_to_empty_now: Option<i64>,
    time_to_full_now: Option<i64>,
    // 微单位组（31 个，÷1e6，对齐 Go Update 第二张 map 的推送序）
    current_boot: Option<i64>,
    current_max: Option<i64>,
    current_now: Option<i64>,
    energy_empty: Option<i64>,
    energy_empty_design: Option<i64>,
    energy_full: Option<i64>,
    energy_full_design: Option<i64>,
    energy_now: Option<i64>,
    voltage_boot: Option<i64>,
    voltage_max: Option<i64>,
    voltage_max_design: Option<i64>,
    voltage_min: Option<i64>,
    voltage_min_design: Option<i64>,
    voltage_now: Option<i64>,
    voltage_ocv: Option<i64>,
    charge_control_limit: Option<i64>,
    charge_control_limit_max: Option<i64>,
    charge_counter: Option<i64>,
    charge_empty: Option<i64>,
    charge_empty_design: Option<i64>,
    charge_full: Option<i64>,
    charge_full_design: Option<i64>,
    charge_now: Option<i64>,
    charge_term_current: Option<i64>,
    constant_charge_current: Option<i64>,
    constant_charge_current_max: Option<i64>,
    constant_charge_voltage: Option<i64>,
    constant_charge_voltage_max: Option<i64>,
    precharge_current: Option<i64>,
    input_current_limit: Option<i64>,
    power_now: Option<i64>,
    // 温度组（8 个，÷10，对齐 Go Update 第三张 map 的推送序）
    temp: Option<i64>,
    temp_alert_max: Option<i64>,
    temp_alert_min: Option<i64>,
    temp_ambient: Option<i64>,
    temp_ambient_max: Option<i64>,
    temp_ambient_min: Option<i64>,
    temp_max: Option<i64>,
    temp_min: Option<i64>,
    // info 字符串属性（Go 侧为 string 零值，缺失即空串）
    capacity_level: String,
    charge_type: String,
    health: String,
    manufacturer: String,
    model_name: String,
    serial_number: String,
    status: String,
    technology: String,
    ps_type: String,
    usb_type: String,
    scope: String,
}

/// 原值组指标后缀（顺序对齐 Go Update 第一张 map）
const RAW_METRICS: [&str; 10] = [
    "authentic",
    "calibrate",
    "capacity",
    "capacity_alert_max",
    "capacity_alert_min",
    "cyclecount",
    "online",
    "present",
    "time_to_empty_seconds",
    "time_to_full_seconds",
];

/// 微单位组指标后缀（顺序对齐 Go Update 第二张 map）
const MICRO_METRICS: [&str; 31] = [
    "current_boot",
    "current_max",
    "current_ampere",
    "energy_empty",
    "energy_empty_design",
    "energy_full",
    "energy_full_design",
    "energy_watthour",
    "voltage_boot",
    "voltage_max",
    "voltage_max_design",
    "voltage_min",
    "voltage_min_design",
    "voltage_volt",
    "voltage_ocv",
    "charge_control_limit",
    "charge_control_limit_max",
    "charge_counter",
    "charge_empty",
    "charge_empty_design",
    "charge_full",
    "charge_full_design",
    "charge_ampere",
    "charge_term_current",
    "constant_charge_current",
    "constant_charge_current_max",
    "constant_charge_voltage",
    "constant_charge_voltage_max",
    "precharge_current",
    "input_current_limit",
    "power_watt",
];

/// 温度组指标后缀（顺序对齐 Go Update 第三张 map）
const TEMP_METRICS: [&str; 8] = [
    "temp_celsius",
    "temp_alert_max_celsius",
    "temp_alert_min_celsius",
    "temp_ambient_celsius",
    "temp_ambient_max_celsius",
    "temp_ambient_min_celsius",
    "temp_max_celsius",
    "temp_min_celsius",
];

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白；无效 UTF-8 以 U+FFFD 替换，对齐 Go ToValidUTF8）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: POWER_SUPPLY_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 对齐 Go strconv.ParseInt(s, 0, 64)：0x/0X 前缀按 16 进制，0b/0B 按
/// 2 进制，0o/0O 按 8 进制，前导 0 按 8 进制（含单个 0），其余 10 进制，
/// 支持正负号（netclass 采集器复用同一实现）
pub(crate) fn parse_int_base0(value: &str) -> Result<i64, std::num::ParseIntError> {
    let (negative, digits) = match value.as_bytes() {
        [b'+', ..] => (false, &value[1..]),
        [b'-', ..] => (true, &value[1..]),
        _ => (false, value),
    };
    let (digits, radix) = match digits.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&digits[2..], 16),
        [b'0', b'b' | b'B', ..] => (&digits[2..], 2),
        [b'0', b'o' | b'O', ..] => (&digits[2..], 8),
        _ => match digits.strip_prefix('0') {
            Some("") => return Ok(0),
            Some(rest) => (rest, 8),
            None => (digits, 10),
        },
    };
    if negative {
        i64::from_str_radix(&format!("-{digits}"), radix)
    } else {
        i64::from_str_radix(digits, radix)
    }
}

/// 构造属性值非法的解析错误
fn value_error(path: &Path, error: std::num::ParseIntError) -> CollectorError {
    CollectorError::Parse {
        file: POWER_SUPPLY_DIR,
        reason: format!("{} 值非法: {error}", path.display()),
    }
}

/// 解析单个电源目录（对齐 procfs parsePowerSupply：仅常规文件参与；
/// 读取失败按 NotFound/Unsupported/InvalidInput 跳过，其余报错；已知数值
/// 属性解析失败报错，未知文件忽略）
fn parse_power_supply(psu_path: &Path) -> Result<PowerSupply, CollectorError> {
    let mut ps = PowerSupply::default();
    for entry in std::fs::read_dir(psu_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let value = match sys_read_file(&path) {
            Ok(value) => value,
            // 对齐 Go：属性不可读（write-only、 EINVAL 等）可安全跳过
            Err(CollectorError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::InvalidInput
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(field) = entry.file_name().into_string().ok() else {
            continue;
        };
        // 已知数值属性的解析（解析失败即报错，对齐 Go ValueParser.Err）
        let numeric = |slot: &mut Option<i64>| -> Result<(), CollectorError> {
            *slot = Some(parse_int_base0(&value).map_err(|error| value_error(&path, error))?);
            Ok(())
        };
        match field.as_str() {
            // 采集器不输出但 Go 侧同样解析（错误行为对齐）的 7 个字段
            "charge_avg" | "current_avg" | "energy_avg" | "power_avg" | "voltage_avg"
            | "time_to_empty_avg" | "time_to_full_avg" => {
                parse_int_base0(&value).map_err(|error| value_error(&path, error))?;
            }
            "authentic" => numeric(&mut ps.authentic)?,
            "calibrate" => numeric(&mut ps.calibrate)?,
            "capacity" => numeric(&mut ps.capacity)?,
            "capacity_alert_max" => numeric(&mut ps.capacity_alert_max)?,
            "capacity_alert_min" => numeric(&mut ps.capacity_alert_min)?,
            "cycle_count" => numeric(&mut ps.cycle_count)?,
            "online" => numeric(&mut ps.online)?,
            "present" => numeric(&mut ps.present)?,
            "time_to_empty_now" => numeric(&mut ps.time_to_empty_now)?,
            "time_to_full_now" => numeric(&mut ps.time_to_full_now)?,
            "current_boot" => numeric(&mut ps.current_boot)?,
            "current_max" => numeric(&mut ps.current_max)?,
            "current_now" => numeric(&mut ps.current_now)?,
            "energy_empty" => numeric(&mut ps.energy_empty)?,
            "energy_empty_design" => numeric(&mut ps.energy_empty_design)?,
            "energy_full" => numeric(&mut ps.energy_full)?,
            "energy_full_design" => numeric(&mut ps.energy_full_design)?,
            "energy_now" => numeric(&mut ps.energy_now)?,
            "voltage_boot" => numeric(&mut ps.voltage_boot)?,
            "voltage_max" => numeric(&mut ps.voltage_max)?,
            "voltage_max_design" => numeric(&mut ps.voltage_max_design)?,
            "voltage_min" => numeric(&mut ps.voltage_min)?,
            "voltage_min_design" => numeric(&mut ps.voltage_min_design)?,
            "voltage_now" => numeric(&mut ps.voltage_now)?,
            "voltage_ocv" => numeric(&mut ps.voltage_ocv)?,
            "charge_control_limit" => numeric(&mut ps.charge_control_limit)?,
            "charge_control_limit_max" => numeric(&mut ps.charge_control_limit_max)?,
            "charge_counter" => numeric(&mut ps.charge_counter)?,
            "charge_empty" => numeric(&mut ps.charge_empty)?,
            "charge_empty_design" => numeric(&mut ps.charge_empty_design)?,
            "charge_full" => numeric(&mut ps.charge_full)?,
            "charge_full_design" => numeric(&mut ps.charge_full_design)?,
            "charge_now" => numeric(&mut ps.charge_now)?,
            "charge_term_current" => numeric(&mut ps.charge_term_current)?,
            "constant_charge_current" => numeric(&mut ps.constant_charge_current)?,
            "constant_charge_current_max" => numeric(&mut ps.constant_charge_current_max)?,
            "constant_charge_voltage" => numeric(&mut ps.constant_charge_voltage)?,
            "constant_charge_voltage_max" => numeric(&mut ps.constant_charge_voltage_max)?,
            "precharge_current" => numeric(&mut ps.precharge_current)?,
            "input_current_limit" => numeric(&mut ps.input_current_limit)?,
            "power_now" => numeric(&mut ps.power_now)?,
            "temp" => numeric(&mut ps.temp)?,
            "temp_alert_max" => numeric(&mut ps.temp_alert_max)?,
            "temp_alert_min" => numeric(&mut ps.temp_alert_min)?,
            "temp_ambient" => numeric(&mut ps.temp_ambient)?,
            "temp_ambient_max" => numeric(&mut ps.temp_ambient_max)?,
            "temp_ambient_min" => numeric(&mut ps.temp_ambient_min)?,
            "temp_max" => numeric(&mut ps.temp_max)?,
            "temp_min" => numeric(&mut ps.temp_min)?,
            "capacity_level" => ps.capacity_level = value,
            "charge_type" => ps.charge_type = value,
            "health" => ps.health = value,
            "manufacturer" => ps.manufacturer = value,
            "model_name" => ps.model_name = value,
            "serial_number" => ps.serial_number = value,
            "status" => ps.status = value,
            "technology" => ps.technology = value,
            "type" => ps.ps_type = value,
            "usb_type" => ps.usb_type = value,
            "scope" => ps.scope = value,
            _ => {}
        }
    }
    Ok(ps)
}

/// 按组推送一个数值指标族样本（divisor：原值组 1、微单位组 1e6、温度组 10）
fn push_group(
    families: &mut [MetricFamily],
    offset: usize,
    names: &[&str],
    values: &[Option<i64>],
    divisor: f64,
    power_supply: &str,
) {
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value else { continue };
        families[offset + index].push_labeled(
            vec![("power_supply".to_string(), power_supply.to_string())],
            *value as f64 / divisor,
        );
    }
    debug_assert_eq!(names.len(), values.len());
}

impl Collector for PowerSupplyClassCollector {
    fn name(&self) -> &'static str {
        "powersupplyclass"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let psu_dir = self.sys_path.join(POWER_SUPPLY_DIR);
        let mut psu_paths: Vec<PathBuf> = match std::fs::read_dir(&psu_dir) {
            // 对齐 Go：不过滤条目，目录内解析失败按错误处理
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect(),
            // power_supply 目录缺失（无电源设备）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        psu_paths.sort();

        // 预建全部指标族：原值组 + 微单位组 + 温度组 + info（共 50 个），
        // help 文本对齐 Go pushPowerSupplyMetric 的 "<name> value of ..." 格式
        let mut families: Vec<MetricFamily> = Vec::with_capacity(50);
        for names in [
            RAW_METRICS.as_slice(),
            MICRO_METRICS.as_slice(),
            TEMP_METRICS.as_slice(),
        ] {
            for name in names {
                families.push(MetricFamily::new(
                    &format!("node_power_supply_{name}"),
                    &format!("{name} value of /sys/class/power_supply/<power_supply>."),
                    MetricType::Gauge,
                ));
            }
        }
        families.push(MetricFamily::new(
            "node_power_supply_info",
            "info of /sys/class/power_supply/<power_supply>.",
            MetricType::Gauge,
        ));

        for psu_path in psu_paths {
            let Some(power_supply) = psu_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let ps = parse_power_supply(&psu_path)?;

            let raw: [Option<i64>; 10] = [
                ps.authentic,
                ps.calibrate,
                ps.capacity,
                ps.capacity_alert_max,
                ps.capacity_alert_min,
                ps.cycle_count,
                ps.online,
                ps.present,
                ps.time_to_empty_now,
                ps.time_to_full_now,
            ];
            let micro: [Option<i64>; 31] = [
                ps.current_boot,
                ps.current_max,
                ps.current_now,
                ps.energy_empty,
                ps.energy_empty_design,
                ps.energy_full,
                ps.energy_full_design,
                ps.energy_now,
                ps.voltage_boot,
                ps.voltage_max,
                ps.voltage_max_design,
                ps.voltage_min,
                ps.voltage_min_design,
                ps.voltage_now,
                ps.voltage_ocv,
                ps.charge_control_limit,
                ps.charge_control_limit_max,
                ps.charge_counter,
                ps.charge_empty,
                ps.charge_empty_design,
                ps.charge_full,
                ps.charge_full_design,
                ps.charge_now,
                ps.charge_term_current,
                ps.constant_charge_current,
                ps.constant_charge_current_max,
                ps.constant_charge_voltage,
                ps.constant_charge_voltage_max,
                ps.precharge_current,
                ps.input_current_limit,
                ps.power_now,
            ];
            let temp: [Option<i64>; 8] = [
                ps.temp,
                ps.temp_alert_max,
                ps.temp_alert_min,
                ps.temp_ambient,
                ps.temp_ambient_max,
                ps.temp_ambient_min,
                ps.temp_max,
                ps.temp_min,
            ];
            push_group(&mut families, 0, &RAW_METRICS, &raw, 1.0, power_supply);
            push_group(
                &mut families,
                RAW_METRICS.len(),
                &MICRO_METRICS,
                &micro,
                1e6,
                power_supply,
            );
            push_group(
                &mut families,
                RAW_METRICS.len() + MICRO_METRICS.len(),
                &TEMP_METRICS,
                &temp,
                10.0,
                power_supply,
            );

            // info：仅收集非空属性（对齐 Go value != "" 判断）；标签键顺序
            // 对齐 Go Update 第四张 map 的声明序
            let values: [(&str, &str); 12] = [
                ("power_supply", power_supply),
                ("capacity_level", ps.capacity_level.as_str()),
                ("charge_type", ps.charge_type.as_str()),
                ("health", ps.health.as_str()),
                ("manufacturer", ps.manufacturer.as_str()),
                ("model_name", ps.model_name.as_str()),
                ("serial_number", ps.serial_number.as_str()),
                ("status", ps.status.as_str()),
                ("technology", ps.technology.as_str()),
                ("type", ps.ps_type.as_str()),
                ("usb_type", ps.usb_type.as_str()),
                ("scope", ps.scope.as_str()),
            ];
            let labels: Vec<(String, String)> = values
                .iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect();
            let info_index = families.len() - 1;
            families[info_index].push_labeled(labels, 1.0);
        }

        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    /// 按完整标签集定位样本值
    fn value_of(family: &MetricFamily, labels: &[(&str, &str)]) -> f64 {
        family
            .samples
            .iter()
            .find(|sample| {
                sample.labels.len() == labels.len()
                    && sample
                        .labels
                        .iter()
                        .all(|(key, value)| labels.iter().any(|(k, v)| k == key && v == value))
            })
            .unwrap_or_else(|| panic!("缺少样本 {labels:?}"))
            .value
    }

    /// 按指标名定位族
    fn family_of<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|family| family.name == name)
            .unwrap_or_else(|| panic!("缺少指标族 {name}"))
    }

    /// 对齐 e2e-output.txt 的 power_supply 段黄金期望
    #[test]
    fn test_collect_matches_fixture() {
        let collector = PowerSupplyClassCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // 10 原值 + 31 微单位 + 8 温度 + 1 info
        assert_eq!(families.len(), 50);

        // 原值组
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_capacity"),
                &[("power_supply", "BAT0")]
            ),
            81.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_cyclecount"),
                &[("power_supply", "BAT0")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_online"),
                &[("power_supply", "AC")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_present"),
                &[("power_supply", "BAT0")]
            ),
            1.0
        );

        // 微单位组（÷1e6）
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_energy_full"),
                &[("power_supply", "BAT0")]
            ),
            45.07
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_energy_full_design"),
                &[("power_supply", "BAT0")]
            ),
            47.52
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_energy_watthour"),
                &[("power_supply", "BAT0")]
            ),
            36.58
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_power_watt"),
                &[("power_supply", "BAT0")]
            ),
            5.002
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_voltage_volt"),
                &[("power_supply", "BAT0")]
            ),
            11.66
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_power_supply_voltage_min_design"),
                &[("power_supply", "BAT0")]
            ),
            10.8
        );

        // info：AC 仅 power_supply/type 两个标签
        let info = family_of(&families, "node_power_supply_info");
        assert_eq!(info.samples.len(), 2);
        let ac = info
            .samples
            .iter()
            .find(|sample| {
                sample.labels.len() == 2
                    && sample
                        .labels
                        .iter()
                        .any(|(k, v)| k == "power_supply" && v == "AC")
                    && sample
                        .labels
                        .iter()
                        .any(|(k, v)| k == "type" && v == "Mains")
            })
            .unwrap_or_else(|| panic!("缺少 AC info 样本"));
        assert_eq!(ac.value, 1.0);
        // info：BAT0 含 8 个非空标签（model_name 的 U+FFFD 来自 fixture 原始字节）
        let bat = info
            .samples
            .iter()
            .find(|sample| {
                sample.labels.len() == 8
                    && sample
                        .labels
                        .iter()
                        .any(|(k, v)| k == "power_supply" && v == "BAT0")
            })
            .unwrap_or_else(|| panic!("缺少 BAT0 info 样本"));
        let get_label = |key: &str| -> String {
            bat.labels
                .iter()
                .find(|(k, _)| k == key)
                .unwrap_or_else(|| panic!("缺少标签 {key}"))
                .1
                .clone()
        };
        assert_eq!(get_label("capacity_level"), "Normal");
        assert_eq!(get_label("manufacturer"), "LGC");
        assert_eq!(get_label("model_name"), "LNV-45N1\u{FFFD}\u{FFFD}");
        assert_eq!(get_label("serial_number"), "38109");
        assert_eq!(get_label("status"), "Discharging");
        assert_eq!(get_label("technology"), "Li-ion");
        assert_eq!(get_label("type"), "Battery");

        // 未采集的组保持空族
        assert!(
            family_of(&families, "node_power_supply_authentic")
                .samples
                .is_empty()
        );
        assert!(
            family_of(&families, "node_power_supply_temp_celsius")
                .samples
                .is_empty()
        );
        assert!(
            family_of(&families, "node_power_supply_current_ampere")
                .samples
                .is_empty()
        );
    }

    /// 电源目录缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_power_supply_dir_yields_empty() {
        let collector =
            PowerSupplyClassCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }

    /// parse_int_base0 对齐 Go ParseInt(s, 0, 64) 的前缀推断
    #[test]
    fn test_parse_int_base0() {
        assert_eq!(
            parse_int_base0("81").unwrap_or_else(|e| panic!("解析失败: {e}")),
            81
        );
        assert_eq!(
            parse_int_base0("0").unwrap_or_else(|e| panic!("解析失败: {e}")),
            0
        );
        assert_eq!(
            parse_int_base0("-42").unwrap_or_else(|e| panic!("解析失败: {e}")),
            -42
        );
        assert_eq!(
            parse_int_base0("0x1b").unwrap_or_else(|e| panic!("解析失败: {e}")),
            27
        );
        assert_eq!(
            parse_int_base0("010").unwrap_or_else(|e| panic!("解析失败: {e}")),
            8
        );
        assert!(parse_int_base0("").is_err());
        assert!(parse_int_base0("x1").is_err());
        // 前导 0 按 8 进制解析，8/9 为非法八进制位
        assert!(parse_int_base0("081").is_err());
    }
}
