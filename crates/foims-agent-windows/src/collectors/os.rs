//! os 采集器（对齐 Go `internal/collector/os/`）。
//!
//! 静态信息（产品名/版本/修订号/安装类型/安装时刻）来自注册表
//! `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`，主机名经
//! GetComputerNameExW 的三种 DNS 形式读取，uptime 由 GetTickCount64
//! 推导。Windows 11 的产品名与版本号处理对齐 Go Build 阶段逻辑。
//!
//! ## 与 Go 的已知偏离
//! - 版本号来源：Go osversion.Get() 用 RtlGetVersion 内核接口，本移植
//!   改读注册表 CurrentMajorVersionNumber / CurrentMinorVersionNumber /
//!   CurrentBuildNumber（常规桌面/服务器系统三者与内核值一致）；
//! - 静态信息每次采集时读取（Go 在 Build 阶段读一次并缓存）；
//! - hostname 三个名字任一读取失败即整轮失败（Go 的 collectHostname
//!   亦如此，仅错误聚合方式不同）；
//! - windows_os_uptime 为 FOIMS 扩展指标（Go 源无此指标，供上报帧使用）。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 注册表子键（Go getWindowsVersion / getInstallTime 同款）
#[cfg(target_os = "windows")]
const SUBKEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// Windows 11 的最早 build 号（Go osversion.V21H2Win11）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const V21H2_WIN11: u32 = 22000;

/// 静态系统信息快照（跨平台纯数据，windows 分支从注册表填充）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct OsStaticInfo {
    /// 产品名（Windows 11 已按 build 号改名）
    pub product: String,
    /// "major.minor.build" 版本串（Go osversion.Get().String()）
    pub version: String,
    pub major_version: String,
    pub minor_version: String,
    pub build_number: String,
    /// UBR 修订号（缺失按 0）
    pub revision: String,
    /// 安装类型（Client/Server…）
    pub installation_type: String,
    /// 安装时刻 Unix 秒（InstallDate，缺失按 0）
    pub install_time: f64,
}

/// Windows 11 的产品名改名：build ≥ 22000 时把首个 " 10 " 换成 " 11 "
/// （对齐 Go strings.Replace(productName, " 10 ", " 11 ", 1)）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows11_rename(product: &str, build: u32) -> String {
    if build < V21H2_WIN11 {
        return product.to_string();
    }
    match product.find(" 10 ") {
        Some(index) => {
            let mut renamed = String::with_capacity(product.len() + 1);
            renamed.push_str(&product[..index]);
            renamed.push_str(" 11 ");
            renamed.push_str(&product[index + " 10 ".len()..]);
            renamed
        }
        None => product.to_string(),
    }
}

/// 构造全部 os 指标族（纯函数，Linux 宿主可测）。
///
/// 族序镜像 Go Collect()：os_info → install_time → hostname；
/// windows_os_uptime 为 FOIMS 扩展，追加在末尾。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_os(
    info: &OsStaticInfo,
    hostname: (&str, &str, &str),
    uptime_secs: f64,
) -> Vec<MetricFamily> {
    // help 中的 \"10\" 为字面反斜杠引号（对齐 Go 原始字符串字面量）
    let mut os_info = MetricFamily::new(
        "windows_os_info",
        "Contains full product name & version in labels. Note that the \"major_version\" for Windows 11 is \\\"10\\\"; a build number greater than 22000 represents Windows 11.",
        MetricType::Gauge,
    );
    os_info.push_labeled(
        vec![
            ("product".to_string(), info.product.clone()),
            ("version".to_string(), info.version.clone()),
            ("major_version".to_string(), info.major_version.clone()),
            ("minor_version".to_string(), info.minor_version.clone()),
            ("build_number".to_string(), info.build_number.clone()),
            ("revision".to_string(), info.revision.clone()),
            (
                "installation_type".to_string(),
                info.installation_type.clone(),
            ),
        ],
        1.0,
    );
    let mut out = Vec::with_capacity(4);
    out.push(os_info);

    let mut install_time = MetricFamily::new(
        "windows_os_install_time_timestamp_seconds",
        "Unix timestamp of OS installation time",
        MetricType::Gauge,
    );
    install_time.push(info.install_time);
    out.push(install_time);

    let mut hostname_family = MetricFamily::new(
        "windows_os_hostname",
        "Labelled system hostname information as provided by ComputerSystem.DNSHostName and ComputerSystem.Domain",
        MetricType::Gauge,
    );
    hostname_family.push_labeled(
        vec![
            ("hostname".to_string(), hostname.0.to_string()),
            ("domain".to_string(), hostname.1.to_string()),
            ("fqdn".to_string(), hostname.2.to_string()),
        ],
        1.0,
    );
    out.push(hostname_family);

    // FOIMS 扩展（Go 源无此指标）
    let mut uptime = MetricFamily::new(
        "windows_os_uptime",
        "Seconds since system boot (FOIMS extension)",
        MetricType::Gauge,
    );
    uptime.push(uptime_secs);
    out.push(uptime);

    out
}

/// FFI 错误 → 采集错误（统一映射为注册表解析错误）
#[cfg(target_os = "windows")]
fn os_error(source: crate::ffi::FfiError) -> CollectorError {
    CollectorError::Parse {
        file: "registry",
        reason: source.to_string(),
    }
}

/// 缺值按默认值处理的 DWORD 读取（对齐 Go UBR/InstallDate 的
/// ErrNotExist → 0；code 2 即 ERROR_FILE_NOT_FOUND）
#[cfg(target_os = "windows")]
fn reg_u32_or(value: &str, default: u32) -> Result<u32, CollectorError> {
    match crate::ffi::reg_read_u32(crate::ffi::REGISTRY_LOCAL_MACHINE, SUBKEY, value) {
        Ok(data) => Ok(data),
        Err(crate::ffi::FfiError::Win32 { code: 2, .. }) => Ok(default),
        Err(error) => Err(os_error(error)),
    }
}

/// 读取静态系统信息（每次采集时读取，见模块文档偏离说明）。
/// ProductName/InstallationType 与 Go 一致做 trim；CurrentBuildNumber
/// 为 REG_SZ，解析失败视为注册表数据异常。
#[cfg(target_os = "windows")]
fn read_static_info() -> Result<OsStaticInfo, CollectorError> {
    use crate::ffi::{self, REGISTRY_LOCAL_MACHINE};

    let product_name =
        ffi::reg_read_string(REGISTRY_LOCAL_MACHINE, SUBKEY, "ProductName").map_err(os_error)?;
    let installation_type =
        ffi::reg_read_string(REGISTRY_LOCAL_MACHINE, SUBKEY, "InstallationType")
            .map_err(os_error)?;
    let revision = reg_u32_or("UBR", 0)?;
    let install_date = reg_u32_or("InstallDate", 0)?;
    let major_version = reg_u32_or("CurrentMajorVersionNumber", 0)?;
    let minor_version = reg_u32_or("CurrentMinorVersionNumber", 0)?;
    let build_text = ffi::reg_read_string(REGISTRY_LOCAL_MACHINE, SUBKEY, "CurrentBuildNumber")
        .map_err(os_error)?;
    let build_number: u32 = build_text
        .trim()
        .parse()
        .map_err(|_| CollectorError::Parse {
            file: "registry",
            reason: format!("CurrentBuildNumber 非法: {build_text}"),
        })?;

    Ok(OsStaticInfo {
        product: windows11_rename(product_name.trim(), build_number),
        version: format!("{major_version}.{minor_version}.{build_number}"),
        major_version: major_version.to_string(),
        minor_version: minor_version.to_string(),
        build_number: build_number.to_string(),
        revision: revision.to_string(),
        installation_type: installation_type.trim().to_string(),
        install_time: f64::from(install_date),
    })
}

/// os 采集器（无状态；静态信息每次采集读取）
pub struct OsCollector {}

impl OsCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)，无配置项）
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for OsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for OsCollector {
    fn name(&self) -> &'static str {
        "os"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        {
            let info = read_static_info()?;
            let hostname = (
                crate::ffi::computer_name(crate::ffi::ComputerNameKind::Hostname)
                    .map_err(os_error)?,
                crate::ffi::computer_name(crate::ffi::ComputerNameKind::Domain)
                    .map_err(os_error)?,
                crate::ffi::computer_name(crate::ffi::ComputerNameKind::FullyQualified)
                    .map_err(os_error)?,
            );
            let uptime_secs = crate::ffi::tick_count_millis() as f64 / 1000.0;
            Ok(emit_os(
                &info,
                (
                    hostname.0.as_str(),
                    hostname.1.as_str(),
                    hostname.2.as_str(),
                ),
                uptime_secs,
            ))
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认静态信息快照
    fn info() -> OsStaticInfo {
        OsStaticInfo {
            product: "Windows 10 Pro".to_string(),
            version: "10.0.22631".to_string(),
            major_version: "10".to_string(),
            minor_version: "0".to_string(),
            build_number: "22631".to_string(),
            revision: "4037".to_string(),
            installation_type: "Client".to_string(),
            install_time: 1_700_000_000.0,
        }
    }

    /// 4 个指标族齐全；os_info 标签序与值、install_time/uptime 直通
    #[test]
    fn test_emit_os_family_layout() {
        let families = emit_os(
            &info(),
            ("HOST", "example.local", "HOST.example.local"),
            9876.5,
        );

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "windows_os_info",
                "windows_os_install_time_timestamp_seconds",
                "windows_os_hostname",
                "windows_os_uptime",
            ]
        );

        // os_info 标签序 product/version/major/minor/build/revision/type
        let os_info = &families[0];
        assert_eq!(os_info.mtype, MetricType::Gauge);
        assert_eq!(
            os_info.samples[0].labels,
            vec![
                ("product".to_string(), "Windows 10 Pro".to_string()),
                ("version".to_string(), "10.0.22631".to_string()),
                ("major_version".to_string(), "10".to_string()),
                ("minor_version".to_string(), "0".to_string()),
                ("build_number".to_string(), "22631".to_string()),
                ("revision".to_string(), "4037".to_string()),
                ("installation_type".to_string(), "Client".to_string()),
            ]
        );
        assert_eq!(os_info.samples[0].value, 1.0);

        let install_time = &families[1];
        assert_eq!(install_time.samples[0].value, 1_700_000_000.0);

        let hostname = &families[2];
        assert_eq!(
            hostname.samples[0].labels,
            vec![
                ("hostname".to_string(), "HOST".to_string()),
                ("domain".to_string(), "example.local".to_string()),
                ("fqdn".to_string(), "HOST.example.local".to_string()),
            ]
        );

        let uptime = &families[3];
        assert_eq!(uptime.samples[0].value, 9876.5);
    }

    /// os_info help 中的 \"10\" 为字面反斜杠引号（对齐 Go 原始字符串字面量）
    #[test]
    fn test_os_info_help_literal() {
        let families = emit_os(&info(), ("H", "D", "F"), 0.0);
        assert_eq!(
            families[0].help,
            "Contains full product name & version in labels. Note that the \"major_version\" for Windows 11 is \\\"10\\\"; a build number greater than 22000 represents Windows 11."
        );
        // 反斜杠引号序列确实存在
        assert!(families[0].help.contains("\\\"10\\\""));
    }

    /// Windows 11 改名：build ≥ 22000 替换首个 " 10 "，其余原样
    #[test]
    fn test_windows11_rename() {
        assert_eq!(windows11_rename("Windows 10 Pro", 22000), "Windows 11 Pro");
        assert_eq!(windows11_rename("Windows 10 Pro", 22631), "Windows 11 Pro");
        // 仅首个匹配被替换（Go strings.Replace n=1）
        assert_eq!(windows11_rename("Windows 10 10", 22000), "Windows 11 10");
        // 无 " 10 " 子串时原样
        assert_eq!(windows11_rename("Windows 10", 22000), "Windows 10");
        assert_eq!(windows11_rename("Windows 10 Pro", 19045), "Windows 10 Pro");
        assert_eq!(windows11_rename("", 22000), "");
    }
}
