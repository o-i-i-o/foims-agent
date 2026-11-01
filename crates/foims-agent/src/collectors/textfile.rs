//! textfile 采集器：文本文件自定义指标。
//!
//! 对齐 node_exporter `textfile.go`（默认启用）：扫描目录下 *.prom 文件
//! （目录经构造注入，对应原版 --collector.textfile.directory），解析为指标
//! 并合并输出；另输出：
//! - `node_textfile_mtime_seconds{file}`：成功读取文件的 mtime（Unix 秒）；
//! - `node_textfile_scrape_error`：任一文件读取出错/解析失败/指标帮助文案
//!   冲突时为 1，否则 0。
//!
//! 合并语义对齐 Go：同名指标帮助文案不一致时丢弃新样本并置错误标记；
//! 缺失 HELP 的指标补 "Metric read from <来源文件列表>"；同族样本标签集
//! 不一致时补空标签（Go 的 allLabelNames 逻辑）。
//!
//! 偏离：summary/histogram 类型无法以平铺样本忠实表达，跳过对应指标族
//! （含其 _sum/_count 尾随指标）并置错误标记；自定义时间戳（原版即整
//! 文件跳过）按原版语义报错跳过。

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType, Sample};

pub struct TextFileCollector {
    dirs: Vec<PathBuf>,
}

impl TextFileCollector {
    /// 生产构造：默认目录为空（仅输出 scrape_error=0，对齐原版默认配置）
    pub fn new() -> Self {
        Self { dirs: Vec::new() }
    }

    /// 指定扫描目录（测试注入 fixture；生产对应 --collector.textfile.directory）
    pub fn with_root(dir: PathBuf) -> Self {
        Self { dirs: vec![dir] }
    }
}

impl Default for TextFileCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析出的文本指标族（help 保留 Option 以支持"无 HELP"语义）
#[derive(Debug, Clone)]
struct TextFamily {
    name: String,
    help: Option<String>,
    mtype: MetricType,
    samples: Vec<Sample>,
    /// summary/histogram（本移植不支持，跳过并置错误标记）
    unsupported: bool,
}

impl TextFamily {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            help: None,
            mtype: MetricType::Untyped,
            samples: Vec::new(),
            unsupported: false,
        }
    }
}

/// 按名定位（或创建）指标族
fn family_entry<'a>(families: &'a mut Vec<TextFamily>, name: &str) -> &'a mut TextFamily {
    if let Some(index) = families.iter().position(|family| family.name == name) {
        &mut families[index]
    } else {
        families.push(TextFamily::new(name));
        let last = families.len() - 1;
        &mut families[last]
    }
}

/// 解析指标样本值（对齐 Prometheus 文本格式的特殊值表示）
fn parse_value(text: &str) -> Result<f64, CollectorError> {
    match text {
        "+Inf" | "Inf" => Ok(f64::INFINITY),
        "-Inf" => Ok(f64::NEG_INFINITY),
        "NaN" => Ok(f64::NAN),
        _ => text.parse::<f64>().map_err(|error| CollectorError::Parse {
            file: "textfile",
            reason: format!("样本值 {text:?} 非法: {error}"),
        }),
    }
}

/// 解析标签值中的转义（对齐 Prometheus 文本格式：\\ \" \n）
fn unescape_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(current) = chars.next() {
        if current != '\\' {
            out.push(current);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// 解析 HELP 行文案转义（\\ 与 \n；与标签值共用同一扫描器，
/// 避免先替换 \\ 再替换 \n 的顺序性双重还原问题）
fn unescape_help(text: &str) -> String {
    unescape_label(text)
}

/// 解析标签段（'{' 之后的部分）：`k="v",...}`；返回标签对与已消费字节数。
/// 标签值原样收集转义序列，交由 unescape_label 统一还原。
fn scan_labels(section: &str) -> Result<(Vec<(String, String)>, usize), CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: "textfile",
        reason: format!("标签段 {section:?}: {reason}"),
    };
    let mut chars = section.char_indices().peekable();
    let mut labels = Vec::new();
    loop {
        // 标签键，读取至 '='
        let mut key = String::new();
        let mut found_eq = false;
        for (_, current) in chars.by_ref() {
            if current == '=' {
                found_eq = true;
                break;
            }
            if current == ',' || current == '}' {
                return Err(invalid("标签键缺少 '='".to_string()));
            }
            key.push(current);
        }
        if !found_eq {
            return Err(invalid("缺少 '='（标签段提前结束）".to_string()));
        }
        // 起始引号
        match chars.next() {
            Some((_, '"')) => {}
            _ => return Err(invalid("标签值缺少起始引号".to_string())),
        }
        // 标签值（保留转义原文直至闭合引号）
        let mut raw = String::new();
        let mut closed = false;
        while let Some((_, current)) = chars.next() {
            match current {
                '"' => {
                    closed = true;
                    break;
                }
                '\\' => {
                    raw.push('\\');
                    if let Some((_, next)) = chars.next() {
                        raw.push(next);
                    }
                }
                other => raw.push(other),
            }
        }
        if !closed {
            return Err(invalid("标签值缺少闭合引号".to_string()));
        }
        labels.push((key.trim().to_string(), unescape_label(&raw)));
        // 分隔符：',' 继续，'}' 结束
        match chars.next() {
            Some((_, ',')) => continue,
            Some((index, '}')) => return Ok((labels, index + 1)),
            _ => return Err(invalid("缺少右花括号".to_string())),
        }
    }
}

/// 标签键白名单：Prometheus 规范 `[a-zA-Z_][a-zA-Z0-9_]*`。
///
/// .prom 文件内容不受信任：非法键名会破坏暴露格式（如含空白/引号
/// 导致下游解析歧义），必须在解析期拒绝
fn is_valid_label_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// 指标名白名单：Prometheus 规范 `[a-zA-Z_:][a-zA-Z0-9_:]*`（比标签键多允许 ':'）
fn is_valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_' || first == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// 解析单个样本行：`name{k="v"} value` 或 `name value`；
/// 含自定义时间戳（额外字段）时报错
fn parse_sample_line(line: &str, families: &mut Vec<TextFamily>) -> Result<(), CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: "textfile",
        reason: format!("样本行 {line:?}: {reason}"),
    };
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'{' {
        index += 1;
    }
    let name = &line[..index];
    if name.is_empty() {
        return Err(invalid("缺少指标名".to_string()));
    }
    if !is_valid_metric_name(name) {
        return Err(invalid(format!("指标名 {name:?} 含非法字符")));
    }
    let mut labels = Vec::new();
    if index < bytes.len() && bytes[index] == b'{' {
        let (parsed, consumed) = scan_labels(&line[index + 1..])?;
        for (key, _) in &parsed {
            if !is_valid_label_key(key) {
                return Err(invalid(format!("标签键 {key:?} 含非法字符")));
            }
        }
        labels = parsed;
        index += 1 + consumed;
    }
    if index >= bytes.len() || !bytes[index].is_ascii_whitespace() {
        return Err(invalid("缺少样本值".to_string()));
    }
    let mut fields = line[index..].split_whitespace();
    let Some(value_text) = fields.next() else {
        return Err(invalid("缺少样本值".to_string()));
    };
    if fields.next().is_some() {
        // 自定义时间戳不支持，对齐 Go 跳过整个文件
        return Err(invalid("含不支持的自定义时间戳".to_string()));
    }
    let value = parse_value(value_text)?;
    family_entry(families, name)
        .samples
        .push(Sample::labeled(labels, value));
    Ok(())
}

/// 解析 .prom 文本为指标族集合
fn parse_prom_text(text: &str) -> Result<Vec<TextFamily>, CollectorError> {
    let invalid = |reason: String| CollectorError::Parse {
        file: "textfile",
        reason,
    };
    let mut families: Vec<TextFamily> = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let Some(name) = parts.next() else {
                return Err(invalid("HELP 行缺少指标名".to_string()));
            };
            let help = parts.next().map(unescape_help);
            family_entry(&mut families, name).help = help;
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let (Some(name), Some(type_text)) = (parts.next(), parts.next()) else {
                return Err(invalid("TYPE 行格式非法".to_string()));
            };
            let family = family_entry(&mut families, name);
            family.mtype = match type_text {
                "counter" => MetricType::Counter,
                "gauge" => MetricType::Gauge,
                "untyped" => MetricType::Untyped,
                // 平铺样本无法表达 summary/histogram，标记不支持
                "summary" | "histogram" => {
                    family.unsupported = true;
                    MetricType::Untyped
                }
                other => return Err(invalid(format!("未知指标类型 {other}"))),
            };
        } else if line.starts_with('#') {
            // 普通注释行跳过
            continue;
        } else {
            parse_sample_line(line, &mut families)?;
        }
    }
    Ok(families)
}

/// 同族样本标签并集补齐：缺失标签补空字符串（对齐 Go allLabelNames；
/// 补齐顺序按标签名排序，保证输出稳定）
fn pad_label_sets(family: &mut TextFamily) {
    if family.samples.len() < 2 {
        return;
    }
    let mut all_names: Vec<String> = Vec::new();
    for sample in &family.samples {
        for (key, _) in &sample.labels {
            if !all_names.iter().any(|name| name == key) {
                all_names.push(key.clone());
            }
        }
    }
    let missing: Vec<String> = all_names
        .into_iter()
        .filter(|name| {
            !family
                .samples
                .iter()
                .all(|sample| sample.labels.iter().any(|(key, _)| key == name))
        })
        .collect();
    if missing.is_empty() {
        return;
    }
    let mut missing = missing;
    missing.sort();
    for sample in &mut family.samples {
        for name in &missing {
            if !sample.labels.iter().any(|(key, _)| key == name) {
                sample.labels.push((name.clone(), String::new()));
            }
        }
    }
}

/// summary/histogram 的 _sum/_count 尾随指标是否应一并跳过
fn is_summary_tail(unsupported: &[String], name: &str) -> bool {
    unsupported.iter().any(|base| {
        name.strip_prefix(base.as_str()) == Some("_sum")
            || name.strip_prefix(base.as_str()) == Some("_count")
    })
}

impl Collector for TextFileCollector {
    fn name(&self) -> &'static str {
        "textfile"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut errored = false;
        // 合并后的指标族（保持文件处理顺序）
        let mut merged: Vec<TextFamily> = Vec::new();
        // 指标名 → 已知 help 与来源文件
        let mut helps: HashMap<String, String> = HashMap::new();
        let mut sources: HashMap<String, Vec<String>> = HashMap::new();
        // 不支持的 summary/histogram 族（用于连带跳过 _sum/_count）
        let mut unsupported: Vec<String> = Vec::new();
        // 成功读取的文件 mtime（路径 → 秒）
        let mut mtimes: Vec<(String, f64)> = Vec::new();

        for dir in &self.dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(_) => {
                    // 空目录（默认配置）不视为错误，其余读取出错置错误标记
                    if !dir.as_os_str().is_empty() {
                        errored = true;
                        tracing::warn!(path = %dir.display(), "textfile 目录读取失败");
                    }
                    continue;
                }
            };
            let mut files: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".prom"))
                })
                .collect();
            // 对齐 os.ReadDir 的文件名序
            files.sort();

            for file in files {
                let file_path = file.display().to_string();
                let text = match std::fs::read_to_string(&file) {
                    Ok(text) => text,
                    Err(error) => {
                        errored = true;
                        tracing::warn!(file = %file_path, error = %error, "textfile 文件读取失败");
                        continue;
                    }
                };
                let families = match parse_prom_text(&text) {
                    Ok(families) => families,
                    Err(error) => {
                        errored = true;
                        tracing::warn!(file = %file_path, error = %error, "textfile 文件解析失败");
                        continue;
                    }
                };
                for mut family in families {
                    if family.unsupported {
                        errored = true;
                        unsupported.push(family.name.clone());
                        tracing::warn!(file = %file_path, metric = %family.name,
                                       "textfile 指标类型不支持（summary/histogram）");
                        continue;
                    }
                    if is_summary_tail(&unsupported, &family.name) {
                        continue;
                    }
                    // 帮助文案冲突 → 丢弃新样本并置错误标记（对齐 Go）
                    let known_help = helps.get(&family.name).cloned();
                    if let Some(help) = &family.help {
                        if let Some(existing) = &known_help
                            && existing != help
                        {
                            errored = true;
                            tracing::warn!(metric = %family.name, file = %file_path,
                                           "textfile 指标帮助文案冲突");
                            continue;
                        }
                        helps.entry(family.name.clone()).or_insert(help.clone());
                    } else if let Some(existing) = known_help {
                        // 同名指标此前已带 HELP → 本族继承之（对齐 Go 的 mfHelp）
                        family.help = Some(existing);
                    }
                    sources
                        .entry(family.name.clone())
                        .or_default()
                        .push(file_path.clone());
                    // 同名指标跨文件合并为单族（样本追加，标签补齐延后统一处理）
                    if let Some(existing) =
                        merged.iter_mut().find(|merged| merged.name == family.name)
                    {
                        existing.samples.append(&mut family.samples);
                        if existing.help.is_none() {
                            existing.help = family.help;
                        }
                    } else {
                        merged.push(family);
                    }
                }
                // 读取与解析均成功才记录 mtime（对齐 Go）
                let mtime = std::fs::metadata(&file)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs_f64());
                if let Some(mtime) = mtime {
                    mtimes.push((file_path, mtime));
                }
            }
        }

        let mut out: Vec<MetricFamily> = Vec::with_capacity(merged.len());
        for mut family in merged {
            // 跨文件合并完成后统一补齐标签并集
            pad_label_sets(&mut family);
            let help = match family.help.or_else(|| helps.get(&family.name).cloned()) {
                Some(help) => help,
                None => {
                    let files = sources
                        .get(&family.name)
                        .map(|files| files.join(", "))
                        .unwrap_or_default();
                    format!("Metric read from {files}")
                }
            };
            let mut metric_family = MetricFamily::new(&family.name, &help, family.mtype);
            metric_family.samples = family.samples;
            out.push(metric_family);
        }

        // mtime 指标（按路径排序）
        mtimes.sort_by(|a, b| a.0.cmp(&b.0));
        if !mtimes.is_empty() {
            let mut mtime_family = MetricFamily::new(
                "node_textfile_mtime_seconds",
                "Unixtime mtime of textfiles successfully read.",
                MetricType::Gauge,
            );
            for (path, mtime) in mtimes {
                mtime_family.push_labeled(vec![("file".to_string(), path)], mtime);
            }
            out.push(mtime_family);
        }

        let mut scrape_error = MetricFamily::new(
            "node_textfile_scrape_error",
            "1 if there was an error opening or reading a file, 0 otherwise",
            MetricType::Gauge,
        );
        scrape_error.push(if errored { 1.0 } else { 0.0 });
        out.push(scrape_error);

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/textfile")
            .join(name)
    }

    /// 按指标名定位族
    fn find<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|family| family.name == name)
            .unwrap_or_else(|| panic!("缺少指标 {name}"))
    }

    #[test]
    fn test_two_metric_files() {
        let collector = TextFileCollector::with_root(fixture_dir("two_metric_files"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // 4 个自定义指标 + mtime + scrape_error
        assert_eq!(families.len(), 6);
        let metric = find(&families, "testmetric1_1");
        assert_eq!(metric.mtype, MetricType::Untyped);
        assert_eq!(metric.samples[0].value, 10.0);
        // 无 HELP → 补 "Metric read from <文件>"
        assert!(metric.help.starts_with("Metric read from "));
        assert!(metric.help.contains("metrics1.prom"));
        assert_eq!(find(&families, "testmetric2_2").samples[0].value, 40.0);
        // 非 .prom 文件被忽略
        assert!(
            families
                .iter()
                .all(|family| !family.name.contains("This file"))
        );
        // scrape_error=0
        assert_eq!(
            find(&families, "node_textfile_scrape_error").samples[0].value,
            0.0
        );
        // mtime 记录了两个 .prom 文件
        let mtime = find(&families, "node_textfile_mtime_seconds");
        assert_eq!(mtime.samples.len(), 2);
        assert!(mtime.samples[0].value > 0.0);
    }

    #[test]
    fn test_label_padding_and_help_merge() {
        let collector = TextFileCollector::with_root(fixture_dir("inconsistent_metrics"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let requests = find(&families, "http_requests_total");
        assert_eq!(requests.mtype, MetricType::Counter);
        // 同族样本标签并集：code/handler/method/foo/baz
        assert_eq!(requests.samples.len(), 17);
        assert_eq!(requests.samples[0].labels.len(), 5);
        assert_eq!(requests.help, "Total number of HTTP requests made.");
        // go_goroutines：无标签样本补 foo=""
        let goroutines = find(&families, "go_goroutines");
        assert_eq!(goroutines.samples.len(), 2);
        assert_eq!(goroutines.samples[1].labels.len(), 1);
        assert_eq!(
            goroutines.samples[1].labels[0],
            ("foo".to_string(), String::new())
        );
    }

    #[test]
    fn test_help_conflict_marks_error() {
        let collector = TextFileCollector::with_root(fixture_dir("metrics_merge_different_help"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // b.prom 文案冲突被丢弃，仅保留 a.prom 的样本
        let events = find(&families, "events_total");
        assert_eq!(events.samples.len(), 2);
        assert_eq!(events.help, "A nice help message.");
        assert_eq!(
            find(&families, "node_textfile_scrape_error").samples[0].value,
            1.0
        );
    }

    #[test]
    fn test_no_help_files_get_synthesized_help() {
        let collector = TextFileCollector::with_root(fixture_dir("metrics_merge_no_help"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        let events = find(&families, "events_total");
        assert!(events.help.starts_with("Metric read from "));
        assert!(events.help.contains("a.prom"));
        assert!(events.help.contains("b.prom"));
        assert_eq!(events.samples.len(), 4);
    }

    #[test]
    fn test_client_side_timestamp_rejects_file() {
        let collector = TextFileCollector::with_root(fixture_dir("client_side_timestamp"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // 含时间戳的文件整体跳过，仅剩 scrape_error
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_textfile_scrape_error");
        assert_eq!(families[0].samples[0].value, 1.0);
    }

    #[test]
    fn test_unsupported_metric_types_skip_family() {
        let collector = TextFileCollector::with_root(fixture_dir("different_metric_types"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        // counter 指标保留；summary 族及其 _sum/_count 尾随指标跳过（移植偏离）
        assert!(families.iter().any(|family| family.name == "events_total"));
        assert!(
            families
                .iter()
                .all(|family| !family.name.starts_with("event_duration_seconds_total"))
        );
        assert_eq!(
            find(&families, "node_textfile_scrape_error").samples[0].value,
            1.0
        );
    }

    #[test]
    fn test_empty_and_missing_dirs() {
        // 空目录：无自定义指标，scrape_error=0
        let collector = TextFileCollector::with_root(fixture_dir("no_metric_files"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_textfile_scrape_error");
        assert_eq!(families[0].samples[0].value, 0.0);

        // 目录不存在：scrape_error=1
        let collector = TextFileCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(
            find(&families, "node_textfile_scrape_error").samples[0].value,
            1.0
        );

        // 默认构造（无目录）：scrape_error=0
        let collector = TextFileCollector::default();
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].samples[0].value, 0.0);
    }

    #[test]
    fn test_parse_value_and_escapes() {
        assert_eq!(parse_value("+Inf").unwrap_or_default(), f64::INFINITY);
        assert_eq!(parse_value("-Inf").unwrap_or_default(), f64::NEG_INFINITY);
        assert!(parse_value("NaN").unwrap_or_default().is_nan());
        assert_eq!(parse_value("1.5").unwrap_or_default(), 1.5);
        assert!(parse_value("abc").is_err());
        assert_eq!(unescape_label("a\\\\b\\\"c\\nd"), "a\\b\"c\nd");
        assert_eq!(unescape_help("h\\\\n"), "h\\n");
    }

    #[test]
    fn test_parse_sample_line_variants() {
        let mut families = Vec::new();
        parse_sample_line("m1 3.5", &mut families).unwrap_or_else(|e| panic!("解析失败: {e}"));
        parse_sample_line("m2{k=\"v,1\",j=\"\\\"q\\\"\"} 2", &mut families)
            .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(families[0].name, "m1");
        assert_eq!(families[0].samples[0].value, 3.5);
        assert_eq!(families[1].samples[0].labels[0].1, "v,1");
        assert_eq!(families[1].samples[0].labels[1].1, "\"q\"");
        // 自定义时间戳 → 错误
        assert!(parse_sample_line("m3 1 123", &mut Vec::new()).is_err());
        // 指标名/标签键白名单
        assert!(parse_sample_line("bad name 1", &mut Vec::new()).is_err());
        assert!(parse_sample_line("m{k ey=\"v\"} 1", &mut Vec::new()).is_err());
        assert!(parse_sample_line("m{ok_1=\"v\"} 1", &mut Vec::new()).is_ok());
    }

    #[test]
    fn test_parse_prom_text_types() {
        let families = parse_prom_text(
            "# HELP m 计数说明\n# TYPE m counter\nm 1\n# TYPE s summary\ns{q=\"0.5\"} 1\ns_sum 2\n",
        )
        .unwrap_or_else(|e| panic!("解析失败: {e}"));
        assert_eq!(families.len(), 3);
        assert_eq!(families[0].mtype, MetricType::Counter);
        assert_eq!(families[0].help.as_deref(), Some("计数说明"));
        assert!(families[1].unsupported);
    }
}
