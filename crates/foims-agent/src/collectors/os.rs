//! os 采集器：os-release 发行版信息。
//!
//! 对齐 node_exporter `os_release.go`（`registerCollector("os", defaultEnabled)`，
//! 默认启用）。读取 <etc>/os-release 解析 KEY=VALUE（去单/双引号并处理双引号内
//! 转义，注释与空行跳过，语义对齐 Go 源使用的 go-envparse）。输出：
//! - `node_os_info`：Gauge 恒 1，12 个标签 build_id/id/id_like/image_id/
//!   image_version/name/pretty_name/variant/variant_id/version/version_codename/
//!   version_id；缺失字段置空字符串但标签保留（与 Go 一致）；
//! - `node_os_version`：VERSION_ID 的 major.minor 前缀解析结果 > 0 时输出，
//!   标签 id/id_like/name；
//! - `node_os_support_end_timestamp_seconds`：SUPPORT_END 非空时输出日期的
//!   Unix 时间戳。
//!
//! 偏离：Go 源按 /etc/os-release → /usr/lib/os-release → SystemVersion.plist
//! 顺序回退，本移植仅读取注入根目录下的 os-release（macOS plist 分支不适用）；
//! 缺 '=' 的行按宽松策略跳过（envparse 会报错，此处对齐 systemd 规范）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const OS_RELEASE_FILE: &str = "os-release";

pub struct OsCollector {
    etc_path: PathBuf,
}

impl OsCollector {
    /// 生产构造：读取真实 /etc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/etc"))
    }

    /// 指定 /etc 根目录（测试注入 fixture）
    pub fn with_root(etc_path: PathBuf) -> Self {
        Self { etc_path }
    }
}

impl Default for OsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// os-release 解析结果（字段对齐 Go 源 osRelease 结构体；缺失键为空字符串）
#[derive(Debug, Default, PartialEq)]
struct OsRelease {
    name: String,
    id: String,
    id_like: String,
    pretty_name: String,
    variant: String,
    variant_id: String,
    version: String,
    version_id: String,
    version_codename: String,
    build_id: String,
    image_id: String,
    image_version: String,
    support_end: String,
}

/// 去除值两侧引号：双引号内处理转义，单引号内字面量；
/// 未加引号的值在首个 '#' 处截断（envparse 的行内注释语义）
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(b'"'), Some(b'"')) if value.len() >= 2 => unescape(&value[1..value.len() - 1]),
        (Some(b'\''), Some(b'\'')) if value.len() >= 2 => value[1..value.len() - 1].to_string(),
        _ => {
            let cut = value.find('#').unwrap_or(value.len());
            value[..cut].trim_end().to_string()
        }
    }
}

/// 处理双引号内的转义序列（对齐 go-envparse：\" \\ \n \r \t；
/// 未知转义原样保留，区别于 envparse 的报错策略）
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(current) = chars.next() {
        if current != '\\' {
            out.push(current);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// 解析 os-release 文本：KEY=VALUE；空行与 # 开头注释行跳过
fn parse_os_release(text: &str) -> OsRelease {
    let mut release = OsRelease::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = unquote(value.trim());
        match key {
            "NAME" => release.name = value,
            "ID" => release.id = value,
            "ID_LIKE" => release.id_like = value,
            "PRETTY_NAME" => release.pretty_name = value,
            "VARIANT" => release.variant = value,
            "VARIANT_ID" => release.variant_id = value,
            "VERSION" => release.version = value,
            "VERSION_ID" => release.version_id = value,
            "VERSION_CODENAME" => release.version_codename = value,
            "BUILD_ID" => release.build_id = value,
            "IMAGE_ID" => release.image_id = value,
            "IMAGE_VERSION" => release.image_version = value,
            "SUPPORT_END" => release.support_end = value,
            _ => {}
        }
    }
    release
}

/// 提取 VERSION_ID 的 major.minor 前缀（对齐 Go 源正则 `^[0-9]+\.?[0-9]*`）；
/// 无数字前缀时返回 None（对应 Go 的 version=0，不输出 node_os_version）
fn major_minor(version_id: &str) -> Option<f64> {
    let bytes = version_id.as_bytes();
    let mut end = 0;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    version_id[..end].parse::<f64>().ok()
}

/// 解析 SUPPORT_END 日期（YYYY-MM-DD，与 Go 的 time.DateOnly 一致，按 UTC 计算）
/// 返回 Unix 时间戳秒；格式非法返回 Parse 错误
fn support_end_timestamp(date: &str) -> Result<f64, CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: OS_RELEASE_FILE,
        reason: format!("SUPPORT_END {reason}: {date}"),
    };
    let parts: Vec<&str> = date.split('-').collect();
    let [year_part, month_part, day_part] = parts.as_slice() else {
        return Err(invalid("日期格式非法（需 YYYY-MM-DD）".to_string()));
    };
    let parse_num = |part: &str, field: &str| -> Result<i64, CollectorError> {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid(format!("{field} 含非数字字符")));
        }
        part.parse::<i64>()
            .map_err(|error| invalid(format!("{field} 解析失败: {error}")))
    };
    let year = parse_num(year_part, "年份")?;
    let month = parse_num(month_part, "月份")?;
    let day = parse_num(day_part, "日")?;
    if !(1..=12).contains(&month) {
        return Err(invalid("月份超出范围".to_string()));
    }
    if !(1..=31).contains(&day) {
        return Err(invalid("日超出范围".to_string()));
    }
    Ok((days_from_civil(year, month, day) * 86_400) as f64)
}

/// 公历日期 → 自 1970-01-01 起的天数（Howard Hinnant days_from_civil 算法）
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl Collector for OsCollector {
    fn name(&self) -> &'static str {
        "os"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = match std::fs::read_to_string(self.etc_path.join(OS_RELEASE_FILE)) {
            Ok(text) => text,
            // os-release 不存在时对齐 Go 源语义：原版依次尝试 /etc 与 /usr/lib
            // 全部缺失时报 ErrNoData
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };
        let release = parse_os_release(&text);

        let mut out = Vec::new();

        // node_os_info：值恒 1，标签缺失字段置空字符串（与 Go 一致）
        let mut info = MetricFamily::new(
            "node_os_info",
            "A metric with a constant '1' value labeled by build_id, id, id_like, image_id, image_version, name, pretty_name, variant, variant_id, version, version_codename, version_id.",
            MetricType::Gauge,
        );
        info.push_labeled(
            vec![
                ("build_id".to_string(), release.build_id.clone()),
                ("id".to_string(), release.id.clone()),
                ("id_like".to_string(), release.id_like.clone()),
                ("image_id".to_string(), release.image_id.clone()),
                ("image_version".to_string(), release.image_version.clone()),
                ("name".to_string(), release.name.clone()),
                ("pretty_name".to_string(), release.pretty_name.clone()),
                ("variant".to_string(), release.variant.clone()),
                ("variant_id".to_string(), release.variant_id.clone()),
                ("version".to_string(), release.version.clone()),
                (
                    "version_codename".to_string(),
                    release.version_codename.clone(),
                ),
                ("version_id".to_string(), release.version_id.clone()),
            ],
            1.0,
        );
        out.push(info);

        // node_os_version：major.minor 前缀解析成功且 > 0 时输出
        if let Some(version) = major_minor(&release.version_id)
            && version > 0.0
        {
            let mut family = MetricFamily::new(
                "node_os_version",
                "Metric containing the major.minor part of the OS version.",
                MetricType::Gauge,
            );
            family.push_labeled(
                vec![
                    ("id".to_string(), release.id.clone()),
                    ("id_like".to_string(), release.id_like.clone()),
                    ("name".to_string(), release.name.clone()),
                ],
                version,
            );
            out.push(family);
        }

        // node_os_support_end_timestamp_seconds：SUPPORT_END 非空时输出
        if !release.support_end.is_empty() {
            let timestamp = support_end_timestamp(&release.support_end)?;
            let mut family = MetricFamily::new(
                "node_os_support_end_timestamp_seconds",
                "Metric containing the end-of-life date timestamp of the OS.",
                MetricType::Gauge,
            );
            family.push(timestamp);
            out.push(family);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/etc")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = OsCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);

        // node_os_info：12 个标签，缺失字段为空字符串
        let info = &families[0];
        assert_eq!(info.name, "node_os_info");
        assert_eq!(info.mtype, MetricType::Gauge);
        assert_eq!(info.samples[0].value, 1.0);
        let labels = &info.samples[0].labels;
        assert_eq!(labels.len(), 12);
        let get = |key: &str| -> String {
            labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("id"), "ubuntu");
        assert_eq!(get("name"), "Ubuntu");
        assert_eq!(get("pretty_name"), "Ubuntu 20.04.2 LTS");
        assert_eq!(get("version"), "20.04.2 LTS (Focal Fossa)");
        assert_eq!(get("version_id"), "20.04");
        assert_eq!(get("version_codename"), "focal");
        assert_eq!(get("id_like"), "debian");
        assert_eq!(get("build_id"), "");
        assert_eq!(get("image_id"), "");

        // node_os_version：VERSION_ID "20.04" → 20.04
        let version = &families[1];
        assert_eq!(version.name, "node_os_version");
        assert_eq!(version.mtype, MetricType::Gauge);
        assert_eq!(version.samples[0].value, 20.04);
    }

    #[test]
    fn test_parse_quotes_and_escapes() {
        let release = parse_os_release(
            "# 注释行\nNAME=\"Distro \\\"X\\\"\"\nVERSION='2.1 LTS'\nID=mydistro # 行内注释\nPRETTY_NAME=Distro\n无等号的行\n",
        );
        assert_eq!(release.name, "Distro \"X\"");
        assert_eq!(release.version, "2.1 LTS");
        assert_eq!(release.id, "mydistro");
        assert_eq!(release.pretty_name, "Distro");
        assert_eq!(release.support_end, "");
    }

    #[test]
    fn test_major_minor() {
        assert_eq!(major_minor("20.04"), Some(20.04));
        assert_eq!(major_minor("9.1.1"), Some(9.1));
        assert_eq!(major_minor("11"), Some(11.0));
        assert_eq!(major_minor(""), None);
        assert_eq!(major_minor("rolling"), None);
    }

    #[test]
    fn test_support_end_timestamp() {
        let value = support_end_timestamp("2030-06-30").unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(value, 1_909_008_000.0);
        assert!(matches!(
            support_end_timestamp("2030/06/30"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            support_end_timestamp("2030-13-01"),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_file_is_nodata() {
        let collector = OsCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
