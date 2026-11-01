//! edac 采集器：EDAC 内存纠错计数。
//!
//! 对齐 node_exporter `edac_linux.go`（默认启用）：遍历
//! /sys/devices/system/edac/mc/mc<N>，输出（Counter）：
//! - `node_edac_correctable_errors_total{controller}` / `_uncorrectable_errors_total`
//!
//!   （mc 目录 ce_count/ue_count）；
//! - `node_edac_csrow_correctable_errors_total{controller,csrow}` /
//!
//!   `_uncorrectable...`（控制器级 noinfo 计数 csrow 记 "unknown"；
//!   csrow 目录 ce_count/ue_count）；
//! - `node_edac_channel_correctable_errors_total{controller,csrow,channel,dimm_label}`
//!
//!   （csrow 下 ch<N>_ce_count，dimm_label 来自 ch<N>_dimm_label，
//!   按原版转换：去 '#'、csrow→_csrow、channel→_channel，缺省 "unknown"）。
//!
//! edac 目录不存在时无样本输出（对齐 Go 的空 Glob 行为）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// EDAC 控制器目录（相对 sys_path）
const EDAC_DIR: &str = "devices/system/edac/mc";

pub struct EdacCollector {
    sys_path: PathBuf,
}

impl EdacCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }
}

impl Default for EdacCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取 u64 计数文件（内容非法按 Go 语义报错）
fn read_count(path: &Path) -> Result<u64, CollectorError> {
    let text = std::fs::read_to_string(path)?;
    text.trim()
        .parse::<u64>()
        .map_err(|error| CollectorError::Parse {
            file: EDAC_DIR,
            reason: format!("{} 计数值非法: {error}", path.display()),
        })
}

/// 从目录名提取编号（mc0 → "0"，csrow12 → "12"）；无编号返回 None
fn dir_number(name: &str, prefix: &str) -> Option<String> {
    let rest = name.strip_prefix(prefix)?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(rest.to_string())
}

/// dimm 标签转换（对齐 Go edacDimmLabel）
fn dimm_label(csrow_dir: &Path, channel: &str) -> String {
    let path = csrow_dir.join(format!("ch{channel}_dimm_label"));
    let Ok(text) = std::fs::read_to_string(path) else {
        return "unknown".to_string();
    };
    text.trim()
        .replace('#', "")
        .replace("csrow", "_csrow")
        .replace("channel", "_channel")
}

impl Collector for EdacCollector {
    fn name(&self) -> &'static str {
        "edac"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mc_dir = self.sys_path.join(EDAC_DIR);
        let mut controller_dirs: Vec<PathBuf> = match std::fs::read_dir(&mc_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.is_dir()
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .and_then(|name| dir_number(name, "mc"))
                            .is_some()
                })
                .collect(),
            // edac 目录缺失（未加载模块）→ 无样本
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        // 对齐 filepath.Glob 的字典序
        controller_dirs.sort();

        let mut correctable = MetricFamily::new(
            "node_edac_correctable_errors_total",
            "Total correctable memory errors.",
            MetricType::Counter,
        );
        let mut uncorrectable = MetricFamily::new(
            "node_edac_uncorrectable_errors_total",
            "Total uncorrectable memory errors.",
            MetricType::Counter,
        );
        let mut csrow_correctable = MetricFamily::new(
            "node_edac_csrow_correctable_errors_total",
            "Total correctable memory errors for this csrow.",
            MetricType::Counter,
        );
        let mut csrow_uncorrectable = MetricFamily::new(
            "node_edac_csrow_uncorrectable_errors_total",
            "Total uncorrectable memory errors for this csrow.",
            MetricType::Counter,
        );
        let mut channel_correctable = MetricFamily::new(
            "node_edac_channel_correctable_errors_total",
            "Total correctable memory errors for this channel.",
            MetricType::Counter,
        );

        for controller in controller_dirs {
            let Some(controller_number) = dir_number(
                controller
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
                "mc",
            ) else {
                continue;
            };
            let controller_label = ("controller".to_string(), controller_number.clone());

            correctable.push_labeled(
                vec![controller_label.clone()],
                read_count(&controller.join("ce_count"))? as f64,
            );
            // 控制器级 noinfo 计数：csrow 标签记 unknown（对齐 Go）
            csrow_correctable.push_labeled(
                vec![
                    controller_label.clone(),
                    ("csrow".to_string(), "unknown".to_string()),
                ],
                read_count(&controller.join("ce_noinfo_count"))? as f64,
            );
            uncorrectable.push_labeled(
                vec![controller_label.clone()],
                read_count(&controller.join("ue_count"))? as f64,
            );
            csrow_uncorrectable.push_labeled(
                vec![
                    controller_label.clone(),
                    ("csrow".to_string(), "unknown".to_string()),
                ],
                read_count(&controller.join("ue_noinfo_count"))? as f64,
            );

            let mut csrow_dirs: Vec<PathBuf> = std::fs::read_dir(&controller)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.is_dir()
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .and_then(|name| dir_number(name, "csrow"))
                            .is_some()
                })
                .collect();
            csrow_dirs.sort();

            for csrow in csrow_dirs {
                let Some(csrow_number) = dir_number(
                    csrow
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default(),
                    "csrow",
                ) else {
                    continue;
                };
                let labels = vec![
                    controller_label.clone(),
                    ("csrow".to_string(), csrow_number.clone()),
                ];
                csrow_correctable
                    .push_labeled(labels.clone(), read_count(&csrow.join("ce_count"))? as f64);
                csrow_uncorrectable
                    .push_labeled(labels.clone(), read_count(&csrow.join("ue_count"))? as f64);

                let mut channel_files: Vec<PathBuf> = std::fs::read_dir(&csrow)?
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .filter(|path| {
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| {
                                name.starts_with("ch") && name.ends_with("_ce_count")
                            })
                    })
                    .collect();
                channel_files.sort();

                for channel_file in channel_files {
                    let file_name = channel_file
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default();
                    // ch<N>_ce_count → 通道编号 N
                    let Some(channel) = file_name
                        .strip_prefix("ch")
                        .and_then(|rest| rest.strip_suffix("_ce_count"))
                    else {
                        continue;
                    };
                    channel_correctable.push_labeled(
                        vec![
                            controller_label.clone(),
                            ("csrow".to_string(), csrow_number.clone()),
                            ("channel".to_string(), channel.to_string()),
                            ("dimm_label".to_string(), dimm_label(&csrow, channel)),
                        ],
                        read_count(&channel_file)? as f64,
                    );
                }
            }
        }

        Ok(vec![
            correctable,
            uncorrectable,
            csrow_correctable,
            csrow_uncorrectable,
            channel_correctable,
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

    #[test]
    fn test_collect_matches_fixture() {
        let collector = EdacCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 5);
        // 控制器计数
        assert_eq!(value_of(&families[0], &[("controller", "0")]), 1.0);
        assert_eq!(value_of(&families[1], &[("controller", "0")]), 5.0);
        // 控制器 noinfo 计数 → csrow=unknown
        assert_eq!(
            value_of(&families[2], &[("controller", "0"), ("csrow", "unknown")]),
            2.0
        );
        assert_eq!(
            value_of(&families[3], &[("controller", "0"), ("csrow", "unknown")]),
            6.0
        );
        // csrow 计数
        assert_eq!(
            value_of(&families[2], &[("controller", "0"), ("csrow", "0")]),
            3.0
        );
        assert_eq!(
            value_of(&families[3], &[("controller", "0"), ("csrow", "2")]),
            5.0
        );
        // 通道计数：dimm_label 按原版转换（去 #，加 _csrow/_channel 下划线）
        assert_eq!(
            value_of(
                &families[4],
                &[
                    ("controller", "0"),
                    ("csrow", "0"),
                    ("channel", "0"),
                    ("dimm_label", "mc0_csrow0_channel0")
                ]
            ),
            0.0
        );
        assert_eq!(families[4].samples.len(), 6);
    }

    #[test]
    fn test_missing_edac_dir_yields_no_samples() {
        let collector = EdacCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.iter().all(|f| f.samples.is_empty()));
    }

    #[test]
    fn test_dimm_label_fallback() {
        // dimm_label 文件缺失 → unknown
        assert_eq!(
            dimm_label(Path::new("/nonexistent-foims-test"), "0"),
            "unknown"
        );
    }
}
