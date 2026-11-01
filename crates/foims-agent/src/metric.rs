//! Prometheus 风格指标模型与文本编码。
//!
//! 指标命名与输出格式对齐 node_exporter（`node_` 命名空间 + Prometheus 文本格式），
//! 便于移植过程中与原版输出逐项对照验证。

use std::fmt::Write as _;

/// 指标类型（node_exporter 实际只使用 Counter/Gauge/Untyped）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Untyped,
}

impl MetricType {
    /// Prometheus 文本格式中的类型字符串
    pub fn as_str(self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Untyped => "untyped",
        }
    }
}

/// 单个样本：标签对 + 值
#[derive(Debug, Clone)]
pub struct Sample {
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

impl Sample {
    /// 无标签样本
    pub fn new(value: f64) -> Self {
        Self {
            labels: Vec::new(),
            value,
        }
    }

    /// 带标签样本
    pub fn labeled(labels: Vec<(String, String)>, value: f64) -> Self {
        Self { labels, value }
    }
}

/// 指标族：同名指标共享 help/type
#[derive(Debug, Clone)]
pub struct MetricFamily {
    pub name: String,
    pub help: String,
    pub mtype: MetricType,
    pub samples: Vec<Sample>,
}

impl MetricFamily {
    /// 创建空指标族
    pub fn new(name: &str, help: &str, mtype: MetricType) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            mtype,
            samples: Vec::new(),
        }
    }

    /// 追加无标签样本
    pub fn push(&mut self, value: f64) {
        self.samples.push(Sample::new(value));
    }

    /// 追加带标签样本
    pub fn push_labeled(&mut self, labels: Vec<(String, String)>, value: f64) {
        self.samples.push(Sample::labeled(labels, value));
    }

    /// 编码为 Prometheus 文本格式（HELP/TYPE 行 + 样本行）。
    /// 空指标族不输出任何行（与 node_exporter 行为一致）。
    pub fn encode_text(&self, out: &mut String) {
        if self.samples.is_empty() {
            return;
        }
        let _ = writeln!(out, "# HELP {} {}", self.name, escape_help(&self.help));
        let _ = writeln!(out, "# TYPE {} {}", self.name, self.mtype.as_str());
        for sample in &self.samples {
            out.push_str(&self.name);
            if !sample.labels.is_empty() {
                out.push('{');
                for (index, (key, value)) in sample.labels.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{key}=\"{}\"", escape_label(value));
                }
                out.push('}');
            }
            let _ = writeln!(out, " {}", format_value(sample.value));
        }
    }
}

/// 全部指标族编码为 Prometheus 文本格式（各族之间以空行分隔）
pub fn encode_text_all(families: &[MetricFamily]) -> String {
    let mut out = String::new();
    for family in families {
        family.encode_text(&mut out);
    }
    out
}

/// HELP 行转义：反斜杠与换行
fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

/// 标签值转义：反斜杠、双引号与换行
fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// 浮点值格式化：对齐 Prometheus 文本格式的特殊值表示
/// （NaN / +Inf / -Inf；普通值复用 Rust 最短表示，整数不带小数点）
pub fn format_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        if value > 0.0 {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        }
    } else {
        format!("{value}")
    }
}
