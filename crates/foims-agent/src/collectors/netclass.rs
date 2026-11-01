//! netclass 采集器：网络设备 sysfs 类信息（/sys/class/net/<iface>/）。
//!
//! 对齐 node_exporter `netclass_linux.go`（默认启用，netClassSysfsUpdate 纯
//! sysfs 路径）与 procfs sysfs net_class.go（v0.23.0）。输出 19 个族：
//! - `node_network_up`（Gauge）：operstate 为 'up' 时 1，否则 0；
//! - `node_network_info`（Gauge，恒 1）：标签
//!   device/address/broadcast/duplex/operstate/adminstate/ifalias，
//!   adminstate 由 flags&1 推导 up/down，flags 缺失记 unknown；
//! - 17 个 `node_network_<property>`（标签 device，help 格式
//!   "Network device property: <name>"）：address_assign_type、carrier、
//!   carrier_changes_total（Counter）、carrier_up_changes_total（Counter）、
//!   carrier_down_changes_total（Counter）、device_id、dormant、flags、
//!   iface_id、iface_link、iface_link_mode、mtu_bytes、name_assign_type、
//!   net_dev_group、speed_bytes、transmit_queue_length、protocol_type。
//!
//! 偏离点：
//! - 未移植 3 个 CLI 参数：`--collector.netclass.netlink`（rtnetlink 路径
//!   netClassRTNLUpdate，Go 默认关闭，不移植）、
//!   `--collector.netclass.ignored-devices`（默认 "^$" 不过滤任何设备）、
//!   `--collector.netclass.ignore-invalid-speed`（固定 false：speed<0 仍输出
//!   speed_bytes）；
//! - class/net 目录缺失时返回空指标族（Go 侧为 ErrNoData）；
//! - 设备按目录名字典序输出（Go map 遍历无序，仅为输出稳定性）；
//! - 非 UTF-8 属性值以 U+FFFD 替换（Go 直接按字节转 string）；
//! - 数值属性解析失败时该属性按缺失处理（Go ValueParser.PInt64 的 Err
//!   未被 netclass 检查，同样静默丢弃）；addr_len 与 phys_port_id/
//!   phys_port_name/phys_switch_id 在 Go 侧解析但采集器不输出，此处直接忽略。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use crate::collectors::powersupplyclass::parse_int_base0;

/// 网络设备目录（相对 sys_path）
const NET_CLASS_DIR: &str = "class/net";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;

/// Go canIgnoreError 匹配的 errno：EPERM/EACCES/ENOENT/EINVAL/ENODATA/
/// EOPNOTSUPP（Rust 无 ENODATA 专属 ErrorKind，按原始 errno 判断）
const IGNORED_ERRNOS: [i32; 6] = [1, 13, 2, 22, 61, 95];

/// 属性指标名与类型（对齐 Go pushMetric 的 getFieldDesc name、类型与推送序）
const PROPERTY_METRICS: [(&str, MetricType); 17] = [
    ("address_assign_type", MetricType::Gauge),
    ("carrier", MetricType::Gauge),
    ("carrier_changes_total", MetricType::Counter),
    ("carrier_up_changes_total", MetricType::Counter),
    ("carrier_down_changes_total", MetricType::Counter),
    ("device_id", MetricType::Gauge),
    ("dormant", MetricType::Gauge),
    ("flags", MetricType::Gauge),
    ("iface_id", MetricType::Gauge),
    ("iface_link", MetricType::Gauge),
    ("iface_link_mode", MetricType::Gauge),
    ("mtu_bytes", MetricType::Gauge),
    ("name_assign_type", MetricType::Gauge),
    ("net_dev_group", MetricType::Gauge),
    ("speed_bytes", MetricType::Gauge),
    ("transmit_queue_length", MetricType::Gauge),
    ("protocol_type", MetricType::Gauge),
];

/// 单个网络设备的 sysfs 解析结果（对齐 procfs NetClassIface 中采集器实际
/// 输出的字段；addr_len 与 3 个 phys_* 字段 Go 侧解析但不输出，此处不保存）
#[derive(Debug, Default)]
struct NetClassIface {
    addr_assign_type: Option<i64>,
    address: String,
    broadcast: String,
    carrier: Option<i64>,
    carrier_changes: Option<i64>,
    carrier_up_count: Option<i64>,
    carrier_down_count: Option<i64>,
    dev_id: Option<i64>,
    dormant: Option<i64>,
    duplex: String,
    flags: Option<i64>,
    if_alias: String,
    if_index: Option<i64>,
    if_link: Option<i64>,
    link_mode: Option<i64>,
    mtu: Option<i64>,
    name_assign_type: Option<i64>,
    net_dev_group: Option<i64>,
    oper_state: String,
    speed: Option<i64>,
    tx_queue_len: Option<i64>,
    ps_type: Option<i64>,
}

pub struct NetClassCollector {
    sys_path: PathBuf,
}

impl NetClassCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for NetClassCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取 sysfs 属性文件（对齐 procfs SysReadFile：单次读取只取前 128 字节、
/// 去首尾空白；无效 UTF-8 以 U+FFFD 替换，见模块头偏离点）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 对齐 Go canIgnoreError：属性不可读（缺失/权限/EINVAL/ENODATA/
/// EOPNOTSUPP 等）可安全跳过，其余错误致命
fn can_ignore_error(error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        Some(errno) => IGNORED_ERRNOS.contains(&errno),
        None => matches!(
            error.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::Unsupported
                | std::io::ErrorKind::InvalidInput
        ),
    }
}

/// 解析单个设备目录（对齐 procfs parseNetClassIface：遍历目录内条目，仅
/// 常规文件参与解析）
fn parse_iface(device_path: &Path) -> Result<NetClassIface, CollectorError> {
    let mut iface = NetClassIface::default();
    for entry in std::fs::read_dir(device_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        let value = match sys_read_file(&entry.path()) {
            Ok(value) => value,
            Err(CollectorError::Io(error)) if can_ignore_error(&error) => continue,
            Err(error) => return Err(error),
        };
        // 对齐 Go ParseNetClassAttribute：数值解析失败静默置缺失
        let numeric = |slot: &mut Option<i64>, text: &str| *slot = parse_int_base0(text).ok();
        match name.as_str() {
            "addr_assign_type" => numeric(&mut iface.addr_assign_type, &value),
            "address" => iface.address = value,
            "broadcast" => iface.broadcast = value,
            "carrier" => numeric(&mut iface.carrier, &value),
            "carrier_changes" => numeric(&mut iface.carrier_changes, &value),
            "carrier_up_count" => numeric(&mut iface.carrier_up_count, &value),
            "carrier_down_count" => numeric(&mut iface.carrier_down_count, &value),
            "dev_id" => numeric(&mut iface.dev_id, &value),
            "dormant" => numeric(&mut iface.dormant, &value),
            "duplex" => iface.duplex = value,
            "flags" => numeric(&mut iface.flags, &value),
            "ifalias" => iface.if_alias = value,
            "ifindex" => numeric(&mut iface.if_index, &value),
            "iflink" => numeric(&mut iface.if_link, &value),
            "link_mode" => numeric(&mut iface.link_mode, &value),
            "mtu" => numeric(&mut iface.mtu, &value),
            "name_assign_type" => numeric(&mut iface.name_assign_type, &value),
            "netdev_group" => numeric(&mut iface.net_dev_group, &value),
            "operstate" => iface.oper_state = value,
            "speed" => numeric(&mut iface.speed, &value),
            "tx_queue_len" => numeric(&mut iface.tx_queue_len, &value),
            "type" => numeric(&mut iface.ps_type, &value),
            _ => {}
        }
    }
    Ok(iface)
}

/// 对齐 Go getAdminState：flags 缺失记 unknown，flags&1（net.FlagUp）为 1
/// 记 up，否则 down
fn admin_state(flags: Option<i64>) -> &'static str {
    match flags {
        None => "unknown",
        Some(flags) if flags & 1 == 1 => "up",
        Some(_) => "down",
    }
}

impl Collector for NetClassCollector {
    fn name(&self) -> &'static str {
        "netclass"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let net_dir = self.sys_path.join(NET_CLASS_DIR);
        let mut device_paths: Vec<PathBuf> = Vec::new();
        match std::fs::read_dir(&net_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    // 对齐 Go NetClassDevices：仅跳过常规文件（ bonding_masters），
                    // 目录与符号链接（如指向 /sys/devices 的 eth0）均参与
                    if entry.file_type()?.is_file() {
                        continue;
                    }
                    device_paths.push(entry.path());
                }
            }
            // class/net 缺失/不可读（无网络设备）→ 空指标族
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        }
        device_paths.sort();

        // 预建全部 19 个指标族：up + info + 17 个属性族
        let mut families: Vec<MetricFamily> = Vec::with_capacity(2 + PROPERTY_METRICS.len());
        families.push(MetricFamily::new(
            "node_network_up",
            "Value is 1 if operstate is 'up', 0 otherwise.",
            MetricType::Gauge,
        ));
        families.push(MetricFamily::new(
            "node_network_info",
            "Non-numeric data from /sys/class/net/<iface>, value is always 1.",
            MetricType::Gauge,
        ));
        for (name, mtype) in PROPERTY_METRICS {
            families.push(MetricFamily::new(
                &format!("node_network_{name}"),
                &format!("Network device property: {name}"),
                mtype,
            ));
        }

        for device_path in device_paths {
            let Some(device) = device_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let iface = parse_iface(&device_path)?;

            let up = if iface.oper_state == "up" { 1.0 } else { 0.0 };
            families[0].push_labeled(vec![("device".to_string(), device.to_string())], up);

            families[1].push_labeled(
                vec![
                    ("device".to_string(), device.to_string()),
                    ("address".to_string(), iface.address.clone()),
                    ("broadcast".to_string(), iface.broadcast.clone()),
                    ("duplex".to_string(), iface.duplex.clone()),
                    ("operstate".to_string(), iface.oper_state.clone()),
                    (
                        "adminstate".to_string(),
                        admin_state(iface.flags).to_string(),
                    ),
                    ("ifalias".to_string(), iface.if_alias.clone()),
                ],
                1.0,
            );

            // 属性族推送（索引 = 2 + PROPERTY_METRICS 中的位置，对齐 Go 推送序）
            let mut push_prop = |index: usize, value: Option<i64>| {
                if let Some(value) = value {
                    families[index].push_labeled(
                        vec![("device".to_string(), device.to_string())],
                        value as f64,
                    );
                }
            };
            push_prop(2, iface.addr_assign_type);
            push_prop(3, iface.carrier);
            push_prop(4, iface.carrier_changes);
            push_prop(5, iface.carrier_up_count);
            push_prop(6, iface.carrier_down_count);
            push_prop(7, iface.dev_id);
            push_prop(8, iface.dormant);
            push_prop(9, iface.flags);
            push_prop(10, iface.if_index);
            push_prop(11, iface.if_link);
            push_prop(12, iface.link_mode);
            push_prop(13, iface.mtu);
            push_prop(14, iface.name_assign_type);
            push_prop(15, iface.net_dev_group);
            // speed<0 时 Go 默认仍输出（--collector.netclass.ignore-invalid-speed
            // 默认 false）：speed_bytes = speed * 1e6 / 8（i64 整除向零截断）
            if let Some(speed) = iface.speed {
                let speed_bytes = speed * 1000 * 1000 / 8;
                push_prop(16, Some(speed_bytes));
            }
            push_prop(17, iface.tx_queue_len);
            push_prop(18, iface.ps_type);
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

    /// 对齐 e2e-output.txt 的 node_network 段格式与 procfs net_class_test.go
    /// 黄金值（fixture 与上游 testdata 合并，属性值一致）
    #[test]
    fn test_collect_matches_fixture() {
        let collector = NetClassCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // up + info + 17 属性族
        assert_eq!(families.len(), 19);

        // 设备字典序：bond0/dmz/eth0/int（eth0 为指向 devices 的符号链接）
        let up = family_of(&families, "node_network_up");
        let devices: Vec<&str> = up
            .samples
            .iter()
            .filter_map(|sample| {
                sample
                    .labels
                    .iter()
                    .find(|(k, _)| k == "device")
                    .map(|(_, v)| v.as_str())
            })
            .collect();
        assert_eq!(devices, vec!["bond0", "dmz", "eth0", "int"]);
        assert_eq!(up.samples.len(), 4);
        for sample in &up.samples {
            assert_eq!(sample.value, 1.0, "operstate 均为 up");
        }

        // info：flags=0x1303 → 4867&1=1 → adminstate=up；ifalias 文件存在但为空
        let info = family_of(&families, "node_network_info");
        assert_eq!(info.samples.len(), 4);
        for device in ["bond0", "dmz", "eth0", "int"] {
            let sample = info
                .samples
                .iter()
                .find(|sample| {
                    sample
                        .labels
                        .iter()
                        .any(|(k, v)| k == "device" && v == device)
                })
                .unwrap_or_else(|| panic!("缺少 {device} info 样本"));
            assert_eq!(sample.value, 1.0);
            let get_label = |key: &str| -> String {
                sample
                    .labels
                    .iter()
                    .find(|(k, _)| k == key)
                    .unwrap_or_else(|| panic!("缺少标签 {key}"))
                    .1
                    .clone()
            };
            assert_eq!(get_label("address"), "01:01:01:01:01:01");
            assert_eq!(get_label("broadcast"), "ff:ff:ff:ff:ff:ff");
            assert_eq!(get_label("duplex"), "full");
            assert_eq!(get_label("operstate"), "up");
            assert_eq!(get_label("adminstate"), "up");
            assert_eq!(get_label("ifalias"), "");
        }

        // 属性族（数值解析对齐 ParseInt base 0：0x1303=4867、0x20=32）
        assert_eq!(family_of(&families, "node_network_flags").samples.len(), 4);
        assert_eq!(
            value_of(
                family_of(&families, "node_network_flags"),
                &[("device", "eth0")]
            ),
            4867.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_device_id"),
                &[("device", "int")]
            ),
            32.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_address_assign_type"),
                &[("device", "bond0")]
            ),
            3.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_carrier"),
                &[("device", "dmz")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_carrier_changes_total"),
                &[("device", "eth0")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_carrier_up_changes_total"),
                &[("device", "int")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_carrier_down_changes_total"),
                &[("device", "bond0")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_dormant"),
                &[("device", "dmz")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_iface_id"),
                &[("device", "bond0")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_iface_link"),
                &[("device", "eth0")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_iface_link_mode"),
                &[("device", "int")]
            ),
            1.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_mtu_bytes"),
                &[("device", "dmz")]
            ),
            1500.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_name_assign_type"),
                &[("device", "bond0")]
            ),
            2.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_net_dev_group"),
                &[("device", "eth0")]
            ),
            0.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_transmit_queue_length"),
                &[("device", "int")]
            ),
            1000.0
        );
        assert_eq!(
            value_of(
                family_of(&families, "node_network_protocol_type"),
                &[("device", "bond0")]
            ),
            1.0
        );

        // speed_bytes：默认 ignore-invalid-speed=false，speed<0 仍输出
        // （bond0 的 speed=-1 → -1000000/8）；其余 1000 → 125000000
        let speed = family_of(&families, "node_network_speed_bytes");
        assert_eq!(speed.samples.len(), 4);
        assert_eq!(value_of(speed, &[("device", "bond0")]), -125_000.0);
        assert_eq!(value_of(speed, &[("device", "dmz")]), 125_000_000.0);
        assert_eq!(value_of(speed, &[("device", "eth0")]), 125_000_000.0);
        assert_eq!(value_of(speed, &[("device", "int")]), 125_000_000.0);
    }

    /// 临时构造部分属性缺失的设备：缺失属性无样本、flags 缺失时 adminstate
    /// 为 unknown、数值解析失败按缺失处理
    #[test]
    fn test_partial_iface_attributes() {
        let root = std::env::temp_dir().join(format!("foims-netclass-test-{}", std::process::id()));
        let device_dir = root.join(NET_CLASS_DIR).join("veth0");
        std::fs::create_dir_all(&device_dir).unwrap_or_else(|e| panic!("建目录失败: {e}"));
        std::fs::write(device_dir.join("operstate"), "down\n")
            .unwrap_or_else(|e| panic!("写文件失败: {e}"));
        std::fs::write(device_dir.join("mtu"), "not-a-number\n")
            .unwrap_or_else(|e| panic!("写文件失败: {e}"));
        // 同目录放一个子目录与非 UTF-8 名称之外的常规内容文件，验证仅常规文件参与
        std::fs::create_dir(device_dir.join("bonding_slave"))
            .unwrap_or_else(|e| panic!("建子目录失败: {e}"));

        let collector = NetClassCollector::with_root(root.clone());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 19);

        // up：operstate=down → 0
        assert_eq!(
            value_of(
                family_of(&families, "node_network_up"),
                &[("device", "veth0")]
            ),
            0.0
        );
        // flags 缺失 → adminstate=unknown
        let info = family_of(&families, "node_network_info");
        let adminstate = info
            .samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(k, v)| k == "device" && v == "veth0")
            })
            .unwrap_or_else(|| panic!("缺少 veth0 info 样本"))
            .labels
            .iter()
            .find(|(k, _)| k == "adminstate")
            .unwrap_or_else(|| panic!("缺少 adminstate 标签"))
            .1
            .clone();
        assert_eq!(adminstate, "unknown");
        // info 的字符串属性缺失记空串
        let address = info
            .samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(k, v)| k == "device" && v == "veth0")
            })
            .unwrap_or_else(|| panic!("缺少 veth0 info 样本"))
            .labels
            .iter()
            .find(|(k, _)| k == "address")
            .unwrap_or_else(|| panic!("缺少 address 标签"))
            .1
            .clone();
        assert_eq!(address, "");
        // mtu 解析失败 → 无样本；speed 缺失 → speed_bytes 无样本
        assert!(
            family_of(&families, "node_network_mtu_bytes")
                .samples
                .is_empty()
        );
        assert!(
            family_of(&families, "node_network_speed_bytes")
                .samples
                .is_empty()
        );

        std::fs::remove_dir_all(&root).unwrap_or_else(|e| panic!("清理临时目录失败: {e}"));
    }

    /// class/net 目录缺失 → 空指标族（偏离 Go ErrNoData）
    #[test]
    fn test_missing_net_dir_yields_empty() {
        let collector = NetClassCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());
    }
}
