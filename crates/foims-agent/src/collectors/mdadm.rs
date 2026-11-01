//! mdadm 采集器：MD/softRAID 设备统计。
//!
//! 对齐 node_exporter `mdadm_linux.go`（默认启用）与 procfs mdstat.go、
//! sysfs mdraid.go（v0.23.0），输出：
//! - /proc/mdstat 解析结果（Gauge，标签 device）：
//!   `node_md_disks_required`（DisksTotal）、`node_md_disks`（标签
//!   state=active/failed/spare；active 来自状态行 [n/m] 的 n，failed/spare
//!   来自设备行 (F)/(S) 计数）、`node_md_state`（固定五标签
//!   active/inactive/recovering/resync/check，命中 ActivityState 的为 1，
//!   resyncing→resync、checking→check，其余如 reshaping 全 0）、
//!   `node_md_blocks`、`node_md_blocks_synced`（默认 = blocks，sync 行提供
//!   (n/m) 时取 n，resync=PENDING/DELAYED 记 0）；
//! - /sys/block/md*/md（Gauge，标签 device）：`node_md_raid_disks`（空
//!   level 或容器类 container/imsm/ddf 不输出）、`node_md_degraded`（仅
//!   raid1/4/5/6/10 读取 degraded 文件，其余按 0）。
//!
//! 偏离点：
//! - mdstat 或 block 目录缺失时返回空指标族（Go 侧为 ErrNoData 且丢弃
//!   已采集输出）；
//! - 不解析 mdstat 的 personalities/mdType/组件设备与 sync 行的百分比、
//!   finish、speed（Go 解析但不输出）；
//! - sysfs 侧仅读取输出所需的 level/raid_disks/degraded，未读 array_state/
//!   uuid/components/chunk_size/sync_action/sync_completed（Go 读取但仅
//!   用于错误传播）；
//! - sysfs 设备按目录名字典序输出（Go filepath.Glob 同为字典序）。

use std::path::{Path, PathBuf};

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// mdstat 文件（相对 proc_path）
const MDSTAT_FILE: &str = "mdstat";
/// MD 设备目录（相对 sys_path）
const BLOCK_DIR: &str = "block";
/// 对齐 procfs SysReadFile 的单次读取上限（字节）
const SYS_READ_LIMIT: usize = 128;

pub struct MdadmCollector {
    proc_path: PathBuf,
    sys_path: PathBuf,
}

impl MdadmCollector {
    /// 生产构造：读取真实 /proc 与 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"), PathBuf::from("/sys"))
    }

    /// 指定 /proc 与 /sys 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf, sys_path: PathBuf) -> Self {
        Self {
            proc_path,
            sys_path,
        }
    }
}

impl Default for MdadmCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个 MD 设备的 mdstat 解析结果（对应 procfs MDStat 的输出相关字段）
struct MdStat {
    name: String,
    activity_state: String,
    disks_active: u64,
    disks_failed: u64,
    disks_spare: u64,
    disks_total: u64,
    blocks_total: u64,
    blocks_synced: u64,
}

/// 构造 mdstat 解析错误
fn mdstat_error(line: &str, reason: &str) -> CollectorError {
    CollectorError::Parse {
        file: MDSTAT_FILE,
        reason: format!("{reason}: {line:?}"),
    }
}

/// 读取 sysfs 文件（对齐 procfs SysReadFile：只取前 128 字节、拒绝 NUL
/// 字节、去首尾空白）
fn sys_read_file(path: &Path) -> Result<String, CollectorError> {
    let bytes = std::fs::read(path)?;
    let bytes = &bytes[..bytes.len().min(SYS_READ_LIMIT)];
    if bytes.contains(&0) {
        return Err(CollectorError::Parse {
            file: BLOCK_DIR,
            reason: format!("{} 含 NUL 字节", path.display()),
        });
    }
    Ok(String::from_utf8_lossy(bytes).trim().to_string())
}

/// 读取文件并去首尾空白（对齐 Go os.ReadFile + TrimSpace）
fn read_trim(path: &Path) -> Result<String, CollectorError> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

/// 解析 mdstat 全文（对齐 procfs parseMDStat 的逐行状态机）
fn parse_mdstat(content: &str) -> Result<Vec<MdStat>, CollectorError> {
    let lines: Vec<&str> = content.split('\n').collect();
    let mut stats = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        // 对齐 Go：跳过空行、' ' 开头行与 "unused" 开头行
        if line.trim().is_empty() || line.starts_with(' ') || line.starts_with("unused") {
            continue;
        }
        // 对齐 Go：Personalities 行仅用于已知 raid 类型登记，跳过
        if line.starts_with("Personalities : ") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(mdstat_error(line, "设备行字段过少"));
        }
        // 对齐 Go：设备行后不足 3 行按错误处理
        if lines.len() <= index + 3 {
            return Err(mdstat_error(line, "设备行之后行数不足"));
        }
        let name = fields[0];
        let mut activity_state = fields[2].to_string();
        // 故障 (F) 与备用 (S) 盘计数来自设备行原文
        let disks_failed = line.matches("(F)").count() as u64;
        let disks_spare = line.matches("(S)").count() as u64;
        let (disks_active, disks_total, blocks_total) = eval_status_line(line, lines[index + 1])?;

        // sync 行索引：bitmap 行顺延一行（对齐 Go）
        let mut sync_index = index + 2;
        if lines[index + 2].contains("bitmap") {
            sync_index += 1;
        }
        let sync_line = lines[sync_index];
        let mut blocks_synced = blocks_total;
        if let Some(state) = sync_state(sync_line) {
            activity_state = state.to_string();
            if sync_line.contains("PENDING") || sync_line.contains("DELAYED") {
                blocks_synced = 0;
            } else {
                blocks_synced = eval_recovery_blocks(sync_line)?;
            }
        }

        stats.push(MdStat {
            name: name.to_string(),
            activity_state,
            disks_active,
            disks_failed,
            disks_spare,
            disks_total,
            blocks_total,
            blocks_synced,
        });
    }
    Ok(stats)
}

/// sync 行状态判定（对齐 Go：recovery/reshape/check 依次优先，其余含
/// resync 的按 resyncing 处理）
fn sync_state(sync_line: &str) -> Option<&'static str> {
    if sync_line.contains("recovery") {
        Some("recovering")
    } else if sync_line.contains("reshape") {
        Some("reshaping")
    } else if sync_line.contains("check") {
        Some("checking")
    } else if sync_line.contains("resync") {
        Some("resyncing")
    } else {
        None
    }
}

/// 解析状态行（对齐 Go evalStatusLine），返回 (active, total, size)
fn eval_status_line(
    device_line: &str,
    status_line: &str,
) -> Result<(u64, u64, u64), CollectorError> {
    let status_fields: Vec<&str> = status_line.split_whitespace().collect();
    let Some(size_field) = status_fields.first() else {
        return Err(mdstat_error(status_line, "状态行为空"));
    };
    let size: u64 = size_field
        .parse()
        .map_err(|_| mdstat_error(status_line, "blocks 数非法"))?;

    // raid0/linear：设备行中 [ 的数量即盘数
    if device_line.contains("raid0") || device_line.contains("linear") {
        let total = device_line.matches('[').count() as u64;
        return Ok((total, total, size));
    }
    // inactive：盘数与同步信息均不可用
    if device_line.contains("inactive") {
        return Ok((0, 0, size));
    }
    // 对齐 Go statusLineRE：(\d+) blocks .*\[(\d+)/(\d+)\] \[([U_]+)\]
    let (total, active, _) = status_line_disks(status_line)
        .ok_or_else(|| mdstat_error(status_line, "状态行缺少 [n/m] [U_] 段"))?;
    Ok((active, total, size))
}

/// 等价 Go statusLineRE `(\d+) blocks .*\[(\d+)/(\d+)\] \[([U_]+)\]`，
/// 返回 (total, active, insync)；`.*` 贪婪 → 取最靠右的 [n/m] + [U_+] 组合
fn status_line_disks(status_line: &str) -> Option<(u64, u64, &str)> {
    // 最左匹配 `\d+ blocks `：第一个前缀为连续数字的 " blocks "（状态行
    // 允许前导空白，对齐 Go 正则的最左匹配语义）
    let mut search_start = 0;
    while let Some(offset) = status_line[search_start..].find(" blocks ") {
        let blocks_at = search_start + offset;
        let before = &status_line[..blocks_at];
        let digits_start = before.len()
            - before
                .trim_end_matches(|digit: char| digit.is_ascii_digit())
                .len();
        if digits_start == before.len() {
            // " blocks " 前无数字，继续向右找
            search_start = blocks_at + 1;
            continue;
        }
        let rest = &status_line[blocks_at + " blocks ".len()..];
        // 从右往左找首个满足 "[n/m] [U_+]" 的 [ 起点（贪婪匹配）
        return rest
            .match_indices('[')
            .rev()
            .find_map(|(pos, _)| parse_bracket_tail(&rest[pos..]));
    }
    None
}

/// 解析 "[n/m] [U_+]" 形式的尾段，返回 (total, active, insync)
fn parse_bracket_tail(tail: &str) -> Option<(u64, u64, &str)> {
    let inner = tail.strip_prefix('[')?;
    let slash = inner.find('/')?;
    let total = inner.get(..slash)?;
    if total.is_empty() || !total.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let after_total = inner.get(slash + 1..)?;
    let close = after_total.find(']')?;
    let active = after_total.get(..close)?;
    if active.is_empty() || !active.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = after_total
        .get(close + 1..)?
        .strip_prefix(' ')?
        .strip_prefix('[')?;
    let insync_end = rest.find(']')?;
    let insync = rest.get(..insync_end)?;
    if insync.is_empty() || !insync.bytes().all(|b| b == b'U' || b == b'_') {
        return None;
    }
    Some((total.parse().ok()?, active.parse().ok()?, insync))
}

/// 从 sync 行提取已同步块数（对齐 Go recoveryLineBlocksRE `\((\d+/\d+)\)`
/// 的首个匹配，取 "/" 前的数字）
fn eval_recovery_blocks(sync_line: &str) -> Result<u64, CollectorError> {
    let is_digits = |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    for (pos, _) in sync_line.match_indices('(') {
        let Some(close) = sync_line[pos..].find(')') else {
            continue;
        };
        let Some(inner) = sync_line.get(pos + 1..pos + close) else {
            continue;
        };
        if let Some((synced, total)) = inner.split_once('/')
            && is_digits(synced)
            && is_digits(total)
        {
            return synced
                .parse()
                .map_err(|_| mdstat_error(sync_line, "sync 块数非法"));
        }
    }
    Err(mdstat_error(sync_line, "sync 行缺少 (n/m) 计数段"))
}

/// 解析 raid_disks 文件内容（对齐 Go：空 → None、纯整数 → Some、
/// "N (M)" reshape 格式取前缀、其余 → None）
fn parse_raid_disks(content: &str) -> Option<u64> {
    if content.is_empty() {
        return None;
    }
    if let Ok(value) = content.parse::<u64>() {
        return Some(value);
    }
    if let Some((prefix, _)) = content.split_once(' ')
        && !prefix.is_empty()
        && let Ok(value) = prefix.parse::<u64>()
    {
        return Some(value);
    }
    None
}

/// 遍历 sysfs block/md*/md 输出 raid_disks/degraded（对齐 procfs sysfs
/// Mdraids 的输出相关部分；level 读取失败按错误传播，对齐 Go）
fn collect_mdraids(
    sys_path: &Path,
    raid_disks: &mut MetricFamily,
    degraded: &mut MetricFamily,
) -> Result<(), CollectorError> {
    let block_dir = sys_path.join(BLOCK_DIR);
    let mut md_paths: Vec<PathBuf> = match std::fs::read_dir(&block_dir) {
        // 对齐 Go filepath.Glob("block/md*/md")：仅含 md 子目录的目录
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("md"))
                    && path.join("md").is_dir()
            })
            .collect(),
        // block 目录缺失（无块设备）→ 两个空指标族
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // 对齐 filepath.Glob 字典序
    md_paths.sort();

    for md_path in md_paths {
        let Some(device) = md_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let md_dir = md_path.join("md");
        let level = sys_read_file(&md_dir.join("level"))?;
        let device_label = vec![("device".to_string(), device.to_string())];
        // 容器类与空 level 无物理盘信息，不输出 raid_disks
        if !matches!(level.as_str(), "container" | "imsm" | "ddf" | "")
            && let Some(disks) = parse_raid_disks(&read_trim(&md_dir.join("raid_disks"))?)
        {
            raid_disks.push_labeled(device_label.clone(), disks as f64);
        }
        // degraded 仅 raid1/4/5/6/10 有效（对齐 Go），其余按 0 输出
        let degraded_disks = if matches!(
            level.as_str(),
            "raid1" | "raid4" | "raid5" | "raid6" | "raid10"
        ) {
            let path = md_dir.join("degraded");
            read_trim(&path)?
                .parse::<u64>()
                .map_err(|_| CollectorError::Parse {
                    file: BLOCK_DIR,
                    reason: format!("{} 值非法", path.display()),
                })?
        } else {
            0
        };
        degraded.push_labeled(device_label, degraded_disks as f64);
    }
    Ok(())
}

impl Collector for MdadmCollector {
    fn name(&self) -> &'static str {
        "mdadm"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut disks_required = MetricFamily::new(
            "node_md_disks_required",
            "Total number of disks of device.",
            MetricType::Gauge,
        );
        let mut disks = MetricFamily::new(
            "node_md_disks",
            "Number of active/failed/spare disks of device.",
            MetricType::Gauge,
        );
        let mut state = MetricFamily::new(
            "node_md_state",
            "Indicates the state of md-device.",
            MetricType::Gauge,
        );
        let mut blocks = MetricFamily::new(
            "node_md_blocks",
            "Total number of blocks on device.",
            MetricType::Gauge,
        );
        let mut blocks_synced = MetricFamily::new(
            "node_md_blocks_synced",
            "Number of blocks synced on device.",
            MetricType::Gauge,
        );

        let mdstat_path = self.proc_path.join(MDSTAT_FILE);
        let content = match std::fs::read_to_string(&mdstat_path) {
            Ok(content) => content,
            // mdstat 缺失（无 MD 设备）→ 空指标族
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        for md in parse_mdstat(&content)? {
            let device_label = vec![("device".to_string(), md.name.clone())];
            disks_required.push_labeled(device_label.clone(), md.disks_total as f64);
            for (label, value) in [
                ("active", md.disks_active),
                ("failed", md.disks_failed),
                ("spare", md.disks_spare),
            ] {
                disks.push_labeled(
                    vec![
                        ("device".to_string(), md.name.clone()),
                        ("state".to_string(), label.to_string()),
                    ],
                    value as f64,
                );
            }
            // state 标签映射（对齐 Go desc：resyncing→resync、checking→check）
            for (label, hit) in [
                ("active", md.activity_state == "active"),
                ("inactive", md.activity_state == "inactive"),
                ("recovering", md.activity_state == "recovering"),
                ("resync", md.activity_state == "resyncing"),
                ("check", md.activity_state == "checking"),
            ] {
                state.push_labeled(
                    vec![
                        ("device".to_string(), md.name.clone()),
                        ("state".to_string(), label.to_string()),
                    ],
                    if hit { 1.0 } else { 0.0 },
                );
            }
            blocks.push_labeled(device_label.clone(), md.blocks_total as f64);
            blocks_synced.push_labeled(device_label, md.blocks_synced as f64);
        }

        let mut raid_disks = MetricFamily::new(
            "node_md_raid_disks",
            "Number of raid disks on device.",
            MetricType::Gauge,
        );
        let mut degraded = MetricFamily::new(
            "node_md_degraded",
            "Number of degraded disks on device.",
            MetricType::Gauge,
        );
        collect_mdraids(&self.sys_path, &mut raid_disks, &mut degraded)?;

        Ok(vec![
            disks_required,
            disks,
            state,
            blocks,
            blocks_synced,
            raid_disks,
            degraded,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_proc() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    fn fixture_sys() -> PathBuf {
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

    /// 对齐 Go mdadm_linux_test.go 的黄金期望
    #[test]
    fn test_collect_matches_fixture() {
        let collector = MdadmCollector::with_root(fixture_proc(), fixture_sys());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 7);

        // node_md_disks_required：17 个 mdstat 设备
        assert_eq!(families[0].samples.len(), 17);
        assert_eq!(value_of(&families[0], &[("device", "md0")]), 2.0);
        assert_eq!(value_of(&families[0], &[("device", "md00")]), 1.0);
        assert_eq!(value_of(&families[0], &[("device", "md10")]), 2.0);
        assert_eq!(value_of(&families[0], &[("device", "md101")]), 3.0);
        assert_eq!(value_of(&families[0], &[("device", "md219")]), 0.0);
        assert_eq!(value_of(&families[0], &[("device", "md3")]), 8.0);
        assert_eq!(value_of(&families[0], &[("device", "md4")]), 0.0);
        assert_eq!(value_of(&families[0], &[("device", "md7")]), 4.0);

        // node_md_disks：active/failed/spare 三标签
        assert_eq!(families[1].samples.len(), 51);
        assert_eq!(
            value_of(&families[1], &[("device", "md3"), ("state", "active")]),
            8.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md3"), ("state", "failed")]),
            0.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md3"), ("state", "spare")]),
            2.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md4"), ("state", "active")]),
            0.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md4"), ("state", "failed")]),
            1.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md4"), ("state", "spare")]),
            1.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md7"), ("state", "active")]),
            3.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md7"), ("state", "failed")]),
            1.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md9"), ("state", "active")]),
            4.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md9"), ("state", "failed")]),
            2.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md9"), ("state", "spare")]),
            1.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md219"), ("state", "spare")]),
            3.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md00"), ("state", "active")]),
            1.0
        );
        assert_eq!(
            value_of(&families[1], &[("device", "md6"), ("state", "active")]),
            1.0
        );

        // node_md_state：17 设备 × 5 固定标签 = 85 样本
        assert_eq!(families[2].samples.len(), 85);
        assert_eq!(
            value_of(&families[2], &[("device", "md0"), ("state", "active")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md4"), ("state", "inactive")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md219"), ("state", "inactive")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md6"), ("state", "recovering")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md8"), ("state", "resync")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md9"), ("state", "resync")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md11"), ("state", "resync")]),
            1.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md201"), ("state", "check")]),
            1.0
        );
        // 未命中标签为 0
        assert_eq!(
            value_of(&families[2], &[("device", "md6"), ("state", "active")]),
            0.0
        );
        assert_eq!(
            value_of(&families[2], &[("device", "md7"), ("state", "resync")]),
            0.0
        );

        // node_md_blocks：17 设备全量
        assert_eq!(families[3].samples.len(), 17);
        assert_eq!(value_of(&families[3], &[("device", "md0")]), 248896.0);
        assert_eq!(value_of(&families[3], &[("device", "md00")]), 4186624.0);
        assert_eq!(value_of(&families[3], &[("device", "md10")]), 314159265.0);
        assert_eq!(value_of(&families[3], &[("device", "md101")]), 322560.0);
        assert_eq!(value_of(&families[3], &[("device", "md11")]), 4190208.0);
        assert_eq!(value_of(&families[3], &[("device", "md12")]), 3886394368.0);
        assert_eq!(value_of(&families[3], &[("device", "md120")]), 2095104.0);
        assert_eq!(value_of(&families[3], &[("device", "md126")]), 1855870976.0);
        assert_eq!(value_of(&families[3], &[("device", "md127")]), 312319552.0);
        assert_eq!(value_of(&families[3], &[("device", "md201")]), 1993728.0);
        assert_eq!(value_of(&families[3], &[("device", "md219")]), 7932.0);
        assert_eq!(value_of(&families[3], &[("device", "md3")]), 5853468288.0);
        assert_eq!(value_of(&families[3], &[("device", "md4")]), 4883648.0);
        assert_eq!(value_of(&families[3], &[("device", "md6")]), 195310144.0);
        assert_eq!(value_of(&families[3], &[("device", "md7")]), 7813735424.0);
        assert_eq!(value_of(&families[3], &[("device", "md8")]), 195310144.0);
        assert_eq!(value_of(&families[3], &[("device", "md9")]), 523968.0);

        // node_md_blocks_synced
        assert_eq!(families[4].samples.len(), 17);
        assert_eq!(value_of(&families[4], &[("device", "md0")]), 248896.0);
        assert_eq!(value_of(&families[4], &[("device", "md11")]), 0.0);
        assert_eq!(value_of(&families[4], &[("device", "md201")]), 114176.0);
        assert_eq!(value_of(&families[4], &[("device", "md219")]), 7932.0);
        assert_eq!(value_of(&families[4], &[("device", "md4")]), 4883648.0);
        assert_eq!(value_of(&families[4], &[("device", "md6")]), 16775552.0);
        assert_eq!(value_of(&families[4], &[("device", "md7")]), 7813735424.0);
        assert_eq!(value_of(&families[4], &[("device", "md8")]), 16775552.0);
        assert_eq!(value_of(&families[4], &[("device", "md9")]), 0.0);

        // node_md_raid_disks：sysfs 6 设备
        assert_eq!(families[5].samples.len(), 6);
        assert_eq!(value_of(&families[5], &[("device", "md0")]), 2.0);
        assert_eq!(value_of(&families[5], &[("device", "md1")]), 2.0);
        assert_eq!(value_of(&families[5], &[("device", "md10")]), 4.0);
        assert_eq!(value_of(&families[5], &[("device", "md4")]), 3.0);
        assert_eq!(value_of(&families[5], &[("device", "md5")]), 3.0);
        assert_eq!(value_of(&families[5], &[("device", "md6")]), 4.0);

        // node_md_degraded：md0 为 raid0 不读文件按 0 输出
        assert_eq!(families[6].samples.len(), 6);
        assert_eq!(value_of(&families[6], &[("device", "md0")]), 0.0);
        assert_eq!(value_of(&families[6], &[("device", "md1")]), 0.0);
        assert_eq!(value_of(&families[6], &[("device", "md10")]), 0.0);
        assert_eq!(value_of(&families[6], &[("device", "md4")]), 0.0);
        assert_eq!(value_of(&families[6], &[("device", "md5")]), 1.0);
        assert_eq!(value_of(&families[6], &[("device", "md6")]), 1.0);
    }

    /// mdstat 解析关键语义：bitmap 行顺延、PENDING/DELAYED 记 0
    #[test]
    fn test_parse_mdstat_sync_semantics() {
        let content = "\
md7 : active raid6 sdb1[0] sde1[3] sdd1[2] sdc1[1](F)
      7813735424 blocks super 1.2 level 6, 512k chunk, algorithm 2 [4/3] [U_UU]
      bitmap: 0/30 pages [0KB], 65536KB chunk

md9 : active raid1 sdc2[2] sdd2[3] sdb2[1] sda2[0] sde[4](F) sdf[5](F) sdg[6](S)
      523968 blocks super 1.2 [4/4] [UUUU]
      resync=DELAYED

md11 : active (auto-read-only) raid1 sdb2[0] sdc2[1] sdc3[2](F) hda[4](S) ssdc2[3](S)
      4190208 blocks super 1.2 [2/2] [UU]
      resync=PENDING

md00 : active raid0 xvdb[0]
      4186624 blocks super 1.2 256k chunks

unused devices: <none>
";
        let stats = parse_mdstat(content).unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(stats.len(), 4);
        // md7：bitmap 行顺延后落到下一设备行，无 sync 语义
        assert_eq!(stats[0].activity_state, "active");
        assert_eq!(stats[0].blocks_synced, 7813735424);
        assert_eq!(stats[0].disks_active, 3);
        assert_eq!(stats[0].disks_total, 4);
        assert_eq!(stats[0].disks_failed, 1);
        // md9：DELAYED → synced=0、resyncing
        assert_eq!(stats[1].activity_state, "resyncing");
        assert_eq!(stats[1].blocks_synced, 0);
        // md11：PENDING → synced=0
        assert_eq!(stats[2].activity_state, "resyncing");
        assert_eq!(stats[2].blocks_synced, 0);
        // md00：raid0 → 盘数取 [ 计数
        assert_eq!(stats[3].disks_active, 1);
        assert_eq!(stats[3].disks_total, 1);
        assert_eq!(stats[3].blocks_synced, 4186624);
    }

    /// 非法输入按 Parse 错误处理（对齐 Go 报错路径）
    #[test]
    fn test_parse_mdstat_errors() {
        // 状态行缺少 [n/m] [U_] 段
        let bad = "md0 : active raid1 sda[0]\n248896 blocks super 1.2\n\nunused\nx\n";
        assert!(matches!(
            parse_mdstat(bad),
            Err(CollectorError::Parse { .. })
        ));
        // blocks 数非法
        let bad_size = "md0 : active raid1 sda[0]\nabc blocks [1/1] [U]\n\nunused\nx\n";
        assert!(matches!(
            parse_mdstat(bad_size),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_missing_files_yield_empty() {
        let collector =
            MdadmCollector::with_root(PathBuf::from("/nonexistent-foims-test"), fixture_sys());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert!(families.is_empty());

        let collector =
            MdadmCollector::with_root(fixture_proc(), PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // mdstat 正常输出，sysfs block 缺失 → raid/degraded 两族为空
        assert_eq!(families.len(), 7);
        assert!(
            families[..5]
                .iter()
                .all(|family| !family.samples.is_empty())
        );
        assert!(families[5..].iter().all(|family| family.samples.is_empty()));
    }

    #[test]
    fn test_parse_raid_disks() {
        assert_eq!(parse_raid_disks("2"), Some(2));
        assert_eq!(parse_raid_disks("11 (10)"), Some(11));
        assert_eq!(parse_raid_disks(""), None);
        assert_eq!(parse_raid_disks("abc"), None);
        assert_eq!(parse_raid_disks("abc (10)"), None);
    }
}
