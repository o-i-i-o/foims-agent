//! filesystem 采集器：文件系统容量与 inode 统计。
//!
//! 对齐 node_exporter `filesystem_common.go` + `filesystem_linux.go`（Linux 路径）：
//! - 指标族 `node_filesystem_{avail_bytes,device_error,files,files_free,free_bytes,readonly,size_bytes}`
//!   全部为 Gauge，help 逐字取自 Go 源；标签 `{device,fstype,mountpoint}`
//!   （原版另有第 4 个标签 `device_error` 承载错误文本，以及 `mount_info` /
//!   `purgeable_bytes` 两个指标族，按移植规格省略）；
//! - 挂载表读取 `/proc/mounts`（原版读 `/proc/1/mountinfo` 并回退
//!   `/proc/self/mountinfo`，字段更细但排除/去重语义一致）；
//! - 排除规则逐字取自 `defMountPointsExcluded` / `defFSTypesExcluded` 两个正则，
//!   以字符串前缀/子树匹配等价实现（不引入 regex 依赖）；
//! - 只读判定使用 statfs 标志位 ST_RDONLY（原版基于挂载选项 ro/emergency_ro）；
//! - 原版的并发 stat worker 与挂起挂载点超时（stuck mounts）机制未移植，按顺序执行。
//!
//! 测试注入：挂载表经 `proc_path` 拼接读取（`with_root`）；statfs 无法注入，故
//! 拆为「解析挂载表→过滤→去重」与「statfs 结果→指标族映射」两段分别测试。

use std::collections::HashSet;
use std::path::PathBuf;

use rustix::fs::StatVfsMountFlags;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 挂载表文件（相对 proc_path）
const MOUNTS_FILE: &str = "mounts";

pub struct FilesystemCollector {
    proc_path: PathBuf,
}

impl FilesystemCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }

    /// 解析挂载表 → 应用排除规则 → 去重，产出待统计的标签集
    fn mount_labels(&self) -> Result<Vec<FsLabels>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(MOUNTS_FILE))?;
        parse_mount_table(&text)
    }
}

impl Default for FilesystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个挂载点的指标标签（对齐 filesystemLabels；挂载选项在统计完成后即被
/// 原版丢弃，本移植不保留）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FsLabels {
    device: String,
    mountpoint: String,
    fstype: String,
}

impl FsLabels {
    /// Prometheus 标签对，顺序 {device,fstype,mountpoint}
    fn label_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("device".to_string(), self.device.clone()),
            ("fstype".to_string(), self.fstype.clone()),
            ("mountpoint".to_string(), self.mountpoint.clone()),
        ]
    }
}

/// 跨位宽归一：rustix 的 f_bsize/f_flags 在 64 位目标为 i64、32 位 musl
/// 目标为 i32，经 Into<i64> 统一转换（i64 走恒等，i32 走扩展转换）。
fn widen_i64(value: impl Into<i64>) -> i64 {
    value.into()
}

/// statfs 结果中参与指标映射的字段（与 rustix::fs::StatFs 解耦，便于用合成值
/// 测试映射逻辑；字段名对应内核 struct statfs 的 f_* 成员）
#[derive(Debug, Clone, Copy)]
struct FsStat {
    /// f_bsize：块大小（跨平台统一归一为 i64）
    bsize: i64,
    /// f_blocks：文件块总数
    blocks: u64,
    /// f_bfree：空闲块数
    bfree: u64,
    /// f_bavail：非特权用户可用块数
    bavail: u64,
    /// f_files：inode 总数
    files: u64,
    /// f_ffree：空闲 inode 数
    ffree: u64,
    /// f_flags：挂载标志位（c_long；只读判定取 RDONLY 位）
    flags: i64,
}

impl FsStat {
    /// 只读判定：statfs 标志位含 ST_RDONLY（rustix 将 ST_* 常量定义为
    /// `StatVfsMountFlags`，而 `StatFs::f_flags` 为原始 c_long，故取其位值）
    fn is_readonly(&self) -> bool {
        self.flags & (StatVfsMountFlags::RDONLY.bits() as i64) != 0
    }
}

/// 单个挂载点的统计上下文：stat 为 None 表示 statfs 失败
/// （对齐原版 device_error=1 并跳过空间/inode 指标的语义）
struct MountStat {
    labels: FsLabels,
    stat: Option<FsStat>,
}

/// 解析 /proc/mounts 文本：逐行提取 device/mountpoint/fstype，应用挂载点与
/// 文件系统类型排除规则（对齐 GetStats 的过滤阶段），并按标签去重
/// （对齐 Update 的 seen 去重）。
fn parse_mount_table(text: &str) -> Result<Vec<FsLabels>, CollectorError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(device) = fields.next() else {
            return Err(CollectorError::Parse {
                file: MOUNTS_FILE,
                reason: format!("缺 device 字段: {line}"),
            });
        };
        let Some(mountpoint) = fields.next() else {
            return Err(CollectorError::Parse {
                file: MOUNTS_FILE,
                reason: format!("缺 mountpoint 字段: {line}"),
            });
        };
        let Some(fstype) = fields.next() else {
            return Err(CollectorError::Parse {
                file: MOUNTS_FILE,
                reason: format!("缺 fstype 字段: {line}"),
            });
        };
        // 第 4 列起为挂载选项与 dump/pass；只读判定改用 statfs 标志位，此处忽略

        // fstab(5) 转义还原（对齐 parseFilesystemLabels：\040 → 空格，\011 → 制表符）
        let mountpoint = unescape_fstab(mountpoint);
        if is_excluded_mountpoint(&mountpoint) {
            tracing::debug!(mountpoint = %mountpoint, "忽略挂载点");
            continue;
        }
        if is_excluded_fstype(fstype) {
            tracing::debug!(fstype = %fstype, "忽略文件系统类型");
            continue;
        }
        let labels = FsLabels {
            device: device.to_string(),
            mountpoint,
            fstype: fstype.to_string(),
        };
        // 同一 device+fstype+mountpoint 只输出一次（对齐原版 seen 逻辑）
        if seen.insert(labels.clone()) {
            out.push(labels);
        }
    }
    Ok(out)
}

/// fstab(5) 挂载点转义还原（对齐 parseFilesystemLabels：仅处理 \040 与 \011）
fn unescape_fstab(path: &str) -> String {
    path.replace("\\040", " ").replace("\\011", "\t")
}

/// 挂载点排除（等价 Go 正则
/// `^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`，
/// 以字符串前缀/子树判断实现，避免引入 regex 依赖）
fn is_excluded_mountpoint(mountpoint: &str) -> bool {
    // `/dev`、`/proc`、`/sys` 三个分支：目录本身或其子树（等价结尾 `($|/)`，
    // "/devtools" 这类非整词前缀不命中）
    for prefix in ["/dev", "/proc", "/sys"] {
        if let Some(rest) = mountpoint.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return true;
        }
    }
    // 其余三个分支要求 `.+`：固定前缀之后至少还有一个字符
    for prefix in [
        "/run/credentials/",
        "/var/lib/docker/",
        "/var/lib/containers/storage/",
    ] {
        if mountpoint
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty())
        {
            return true;
        }
    }
    false
}

/// 文件系统类型排除（等价 Go 正则
/// `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$`，
/// `cgroup2?` 展开为 cgroup/cgroup2 两个候选后整词比对，顺序保持原正则）
const EXCLUDED_FILESYSTEMS: [&str; 25] = [
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "fusectl",
    "hugetlbfs",
    "iso9660",
    "mqueue",
    "nsfs",
    "overlay",
    "proc",
    "procfs",
    "pstore",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "squashfs",
    "erofs",
    "sysfs",
    "tracefs",
];

/// 文件系统类型是否在默认排除名单内
fn is_excluded_fstype(fstype: &str) -> bool {
    EXCLUDED_FILESYSTEMS.contains(&fstype)
}

/// 由统计上下文构造指标族；族顺序与样本推送顺序对齐原版 Update：
/// device_error、readonly 先行，statfs 失败的挂载点跳过空间/inode 指标。
fn build_metric_families(mounts: &[MountStat]) -> Vec<MetricFamily> {
    let mut device_error = MetricFamily::new(
        "node_filesystem_device_error",
        "Whether an error occurred while getting statistics for the given device.",
        MetricType::Gauge,
    );
    let mut readonly = MetricFamily::new(
        "node_filesystem_readonly",
        "Filesystem read-only status.",
        MetricType::Gauge,
    );
    let mut size = MetricFamily::new(
        "node_filesystem_size_bytes",
        "Filesystem size in bytes.",
        MetricType::Gauge,
    );
    let mut free = MetricFamily::new(
        "node_filesystem_free_bytes",
        "Filesystem free space in bytes.",
        MetricType::Gauge,
    );
    let mut avail = MetricFamily::new(
        "node_filesystem_avail_bytes",
        "Filesystem space available to non-root users in bytes.",
        MetricType::Gauge,
    );
    let mut files = MetricFamily::new(
        "node_filesystem_files",
        "Filesystem total file nodes.",
        MetricType::Gauge,
    );
    let mut files_free = MetricFamily::new(
        "node_filesystem_files_free",
        "Filesystem total free file nodes.",
        MetricType::Gauge,
    );

    for mount in mounts {
        let labels = mount.labels.label_pairs();
        match &mount.stat {
            Some(stat) => {
                device_error.push_labeled(labels.clone(), 0.0);
                readonly.push_labeled(labels.clone(), if stat.is_readonly() { 1.0 } else { 0.0 });
                let bsize = stat.bsize as f64;
                size.push_labeled(labels.clone(), stat.blocks as f64 * bsize);
                free.push_labeled(labels.clone(), stat.bfree as f64 * bsize);
                avail.push_labeled(labels.clone(), stat.bavail as f64 * bsize);
                files.push_labeled(labels.clone(), stat.files as f64);
                files_free.push_labeled(labels, stat.ffree as f64);
            }
            None => {
                device_error.push_labeled(labels.clone(), 1.0);
                readonly.push_labeled(labels, 0.0);
            }
        }
    }
    vec![device_error, readonly, size, free, avail, files, files_free]
}

impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let labels = self.mount_labels()?;
        // 逐挂载点 statfs；失败按原版语义记 device_error=1 并跳过空间/inode 指标
        let mounts: Vec<MountStat> = labels
            .into_iter()
            .map(|label| {
                let stat = match rustix::fs::statfs(label.mountpoint.as_str()) {
                    Ok(raw) => Some(FsStat {
                        bsize: widen_i64(raw.f_bsize),
                        blocks: raw.f_blocks,
                        bfree: raw.f_bfree,
                        bavail: raw.f_bavail,
                        files: raw.f_files,
                        ffree: raw.f_ffree,
                        flags: widen_i64(raw.f_flags),
                    }),
                    Err(error) => {
                        tracing::debug!(
                            mountpoint = %label.mountpoint,
                            error = %error,
                            "statfs 失败"
                        );
                        None
                    }
                };
                MountStat {
                    labels: label,
                    stat,
                }
            })
            .collect();
        Ok(build_metric_families(&mounts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn test_mount_labels_from_fixture() {
        let collector = FilesystemCollector::with_root(fixture_root());
        let labels = collector
            .mount_labels()
            .unwrap_or_else(|e| panic!("解析挂载表失败: {e}"));

        // /dev/shm、/proc、/sys、/sys/fs/cgroup、/proc/sys/fs/binfmt_misc、
        // /var/lib/docker/... 按挂载点排除；/mnt/overlay-test 按 fstype(overlay) 排除；
        // \040 转义还原为空格；两行重复挂载去重为一
        let mountpoints: Vec<&str> = labels.iter().map(|l| l.mountpoint.as_str()).collect();
        assert_eq!(mountpoints, vec!["/", "/boot/efi", "/mnt/data disk"]);

        assert_eq!(labels[0].device, "/dev/nvme0n1p2");
        assert_eq!(labels[0].fstype, "ext4");
        assert_eq!(labels[1].device, "/dev/nvme0n1p1");
        assert_eq!(labels[1].fstype, "vfat");
        assert_eq!(labels[2].device, "/dev/sdb1");
        assert_eq!(labels[2].fstype, "ext4");
    }

    #[test]
    fn test_parse_rejects_malformed_line() {
        assert!(matches!(
            parse_mount_table("/dev/sda1 /only-two"),
            Err(CollectorError::Parse { file: "mounts", .. })
        ));
        // 空行与空白行跳过，不报错
        let labels = parse_mount_table("\n   \n")
            .unwrap_or_else(|error| panic!("空白行应跳过而非报错: {error}"));
        assert!(labels.is_empty());
    }

    #[test]
    fn test_is_excluded_mountpoint() {
        // 目录本身与子树
        assert!(is_excluded_mountpoint("/dev"));
        assert!(is_excluded_mountpoint("/dev/shm"));
        assert!(is_excluded_mountpoint("/proc"));
        assert!(is_excluded_mountpoint("/proc/sys"));
        assert!(is_excluded_mountpoint("/sys"));
        assert!(is_excluded_mountpoint("/sys/fs/cgroup"));
        // .+ 分支：固定前缀后至少一个字符
        assert!(is_excluded_mountpoint("/run/credentials/systemd-x.service"));
        assert!(is_excluded_mountpoint("/var/lib/docker/overlay2/x/merged"));
        assert!(is_excluded_mountpoint(
            "/var/lib/containers/storage/overlay/x"
        ));
        // 非整词前缀不命中（等价正则 ($|/) 边界）
        assert!(!is_excluded_mountpoint("/devtools"));
        assert!(!is_excluded_mountpoint("/procroot"));
        // .+ 要求至少一个字符
        assert!(!is_excluded_mountpoint("/run/credentials"));
        assert!(!is_excluded_mountpoint("/var/lib/docker"));
        // 普通路径不排除
        assert!(!is_excluded_mountpoint("/"));
        assert!(!is_excluded_mountpoint("/home"));
        assert!(!is_excluded_mountpoint("/mnt/overlay-test"));
    }

    #[test]
    fn test_is_excluded_fstype() {
        for fstype in [
            "autofs", "bpf", "cgroup", "cgroup2", "overlay", "proc", "squashfs", "erofs", "sysfs",
            "tracefs",
        ] {
            assert!(is_excluded_fstype(fstype), "{fstype} 应被排除");
        }
        for fstype in ["ext4", "xfs", "vfat", "btrfs", "zfs", "tmpfs"] {
            assert!(!is_excluded_fstype(fstype), "{fstype} 不应被排除");
        }
    }

    #[test]
    fn test_build_metric_families_with_synthetic_stat() {
        let labels = FsLabels {
            device: "/dev/sda1".to_string(),
            mountpoint: "/".to_string(),
            fstype: "ext4".to_string(),
        };
        let stat = FsStat {
            bsize: 4096,
            blocks: 100,
            bfree: 60,
            bavail: 50,
            files: 1000,
            ffree: 800,
            flags: 0,
        };
        assert!(!stat.is_readonly());
        let readonly_stat = FsStat {
            flags: StatVfsMountFlags::RDONLY.bits() as i64,
            ..stat
        };
        assert!(readonly_stat.is_readonly());

        let mounts = vec![MountStat {
            labels: labels.clone(),
            stat: Some(stat),
        }];
        let families = build_metric_families(&mounts);

        // 族顺序对齐原版 Update 的输出顺序
        let names: Vec<&str> = families.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "node_filesystem_device_error",
                "node_filesystem_readonly",
                "node_filesystem_size_bytes",
                "node_filesystem_free_bytes",
                "node_filesystem_avail_bytes",
                "node_filesystem_files",
                "node_filesystem_files_free",
            ]
        );
        assert!(families.iter().all(|f| f.mtype == MetricType::Gauge));

        // 标签与值映射（块数 × 块大小）
        let expected_labels = vec![
            ("device".to_string(), "/dev/sda1".to_string()),
            ("fstype".to_string(), "ext4".to_string()),
            ("mountpoint".to_string(), "/".to_string()),
        ];
        for family in &families {
            assert_eq!(family.samples.len(), 1, "{} 样本数", family.name);
            assert_eq!(family.samples[0].labels, expected_labels);
        }
        assert_eq!(families[0].samples[0].value, 0.0);
        assert_eq!(families[1].samples[0].value, 0.0);
        assert_eq!(families[2].samples[0].value, 100.0 * 4096.0);
        assert_eq!(families[3].samples[0].value, 60.0 * 4096.0);
        assert_eq!(families[4].samples[0].value, 50.0 * 4096.0);
        assert_eq!(families[5].samples[0].value, 1000.0);
        assert_eq!(families[6].samples[0].value, 800.0);
    }

    #[test]
    fn test_build_metric_families_on_stat_error() {
        let mounts = vec![MountStat {
            labels: FsLabels {
                device: "/dev/sdc1".to_string(),
                mountpoint: "/mnt/dead".to_string(),
                fstype: "ext4".to_string(),
            },
            stat: None,
        }];
        let families = build_metric_families(&mounts);

        // 失败挂载点：device_error=1、readonly=0，空间/inode 指标不输出样本
        assert_eq!(families[0].samples[0].value, 1.0);
        assert_eq!(families[1].samples[0].value, 0.0);
        for family in &families[2..] {
            assert!(family.samples.is_empty(), "{} 不应有样本", family.name);
        }
        assert_eq!(families[0].samples[0].labels[0].1, "/dev/sdc1");
    }

    #[test]
    fn test_collect_missing_mounts_file_is_io_error() {
        let collector = FilesystemCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
