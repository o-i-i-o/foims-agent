# foims-agent

FOIMS 主机指标采集 Agent：Linux 采集器集合为 Prometheus node_exporter 的
Rust 重写，Windows 采集器集合移植自 Prometheus windows_exporter，经
HTTP/3（QUIC mTLS）向 FOIMS 服务端上报，也支持文本/JSON 本地输出。

- 第三方移植来源与许可归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
  （node_exporter：Apache-2.0；windows_exporter：MIT）。
- 本项目以 GPL-3.0-or-later 发布，见 [LICENSE](LICENSE)。
- 版本与变更记录见 [docs/dev_version.md](docs/dev_version.md)。
