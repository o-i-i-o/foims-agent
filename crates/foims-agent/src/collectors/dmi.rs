//! dmi 采集器：桌面管理接口（DMI/SMBIOS）信息。
//!
//! 对齐 node_exporter `dmi.go`（默认启用）：读取 /sys/class/dmi/id/ 下
//! 20 个属性文件，输出 `node_dmi_info{...}`（Gauge 恒 1，文件存在的属性
//! 作为标签；文件缺失的属性不出现在标签中）。无任何属性时返回 NoData。
//! 属性值经 UTF-8 有效性处理（无效字节替换为 U+FFFD，对齐 Go 的
//! strings.ToValidUTF8）。标签顺序按 Go 源列表固定排序（原版 map 迭代
//! 顺序随机，此处取确定性顺序）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// DMI id 目录（相对 sys_path）
const DMI_DIR: &str = "class/dmi/id";

/// DMI 属性列表（顺序 = 标签输出顺序，与 Go 源列表一致；
/// 标签名与 sysfs 文件名基本一致，仅 system_vendor 对应 sys_vendor 文件）
const DMI_LABELS: [(&str, &str); 20] = [
    ("bios_date", "bios_date"),
    ("bios_release", "bios_release"),
    ("bios_vendor", "bios_vendor"),
    ("bios_version", "bios_version"),
    ("board_asset_tag", "board_asset_tag"),
    ("board_name", "board_name"),
    ("board_serial", "board_serial"),
    ("board_vendor", "board_vendor"),
    ("board_version", "board_version"),
    ("chassis_asset_tag", "chassis_asset_tag"),
    ("chassis_serial", "chassis_serial"),
    ("chassis_vendor", "chassis_vendor"),
    ("chassis_version", "chassis_version"),
    ("product_family", "product_family"),
    ("product_name", "product_name"),
    ("product_serial", "product_serial"),
    ("product_sku", "product_sku"),
    ("product_uuid", "product_uuid"),
    ("product_version", "product_version"),
    ("system_vendor", "sys_vendor"),
];

pub struct DmiCollector {
    sys_path: PathBuf,
}

impl DmiCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for DmiCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for DmiCollector {
    fn name(&self) -> &'static str {
        "dmi"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut labels: Vec<(String, String)> = Vec::with_capacity(DMI_LABELS.len());
        for (label, file) in DMI_LABELS {
            let path = self.sys_path.join(DMI_DIR).join(file);
            // 文件缺失 → 该属性不出现在标签中（对齐 procfs 的 nil 处理）
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let value = String::from_utf8_lossy(&bytes).trim().to_string();
                    labels.push((label.to_string(), value));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if labels.is_empty() {
            return Err(CollectorError::NoData);
        }

        let mut family = MetricFamily::new(
            "node_dmi_info",
            "A metric with a constant '1' value labeled by bios_date, bios_release, bios_vendor, bios_version, board_asset_tag, board_name, board_serial, board_vendor, board_version, chassis_asset_tag, chassis_serial, chassis_vendor, chassis_version, product_family, product_name, product_serial, product_sku, product_uuid, product_version, system_vendor if provided by DMI.",
            MetricType::Gauge,
        );
        family.push_labeled(labels, 1.0);
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
        let collector = DmiCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        let family = &families[0];
        assert_eq!(family.name, "node_dmi_info");
        assert_eq!(family.mtype, MetricType::Gauge);
        assert_eq!(family.samples[0].value, 1.0);
        let labels = &family.samples[0].labels;
        // fixture：board_asset_tag 文件缺失 → 19 个标签
        assert_eq!(labels.len(), 19);
        let get = |key: &str| -> String {
            labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("system_vendor"), "Dell Inc.");
        assert_eq!(get("product_name"), "PowerEdge R6515");
        assert_eq!(get("bios_date"), "04/12/2021");
        // 空文件属性保留为空字符串标签
        assert_eq!(get("chassis_asset_tag"), "");
        // product_version 含无效 UTF-8 字节 → 替换字符
        assert!(get("product_version").contains('\u{FFFD}'));
        assert!(!labels.iter().any(|(k, _)| k == "board_asset_tag"));
    }

    #[test]
    fn test_missing_dmi_dir_is_nodata() {
        let collector = DmiCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
