# foims-agent 采集器移植清单

node_exporter/windows_exporter（Go）→ foims-agent（Rust）采集器移植对照表。本文只负责移植进度跟踪。


## 已知偏离汇总

- 正则类过滤（netdev 设备过滤、filesystem 排除规则、hwmon include/exclude、
  netstat/vmstat 字段过滤、arp 设备过滤）以字符串/前缀匹配等价实现，
  未引入 regex 依赖；
- cpu 采集器未移植 cgroup 节流指标与 idle 回跳缓存（无状态实现）；
- netdev/filesystem 未移植并发抓取与卡死超时机制；
- time 未输出 `node_time_zone_offset_seconds`（待 chrono/tz 依赖决策）；
- textfile 仅支持 counter/gauge/untyped，summary/histogram 跳过并置
  `node_textfile_scrape_error` 1；目录为单目录注入（原版支持多目录与 glob）；
- stat 的 `node_boot_time_seconds` 由 boottime 采集器输出，避免重复指标族
  （原版两采集器均输出）；
- arp 默认走 /proc/net/arp（原版默认 netlink），统计范围限于 IPv4 邻居；
- selinux config mode 缺省值取 go-selinux 的 permissive(2) 兜底；
- 测试为各采集器文件内的 `#[cfg(test)]` 模块，fixture 数据位于
  `crates/foims-agent/tests/fixtures/`，`cargo test -p foims-agent` 全绿。
