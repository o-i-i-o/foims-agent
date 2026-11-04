# FOIMS Agent 版本记录

版本号规则：见主仓 docs/dev_version.md（格式一致）；agent 家族版本独立自
管理，取本工作空间根 `Cargo.toml` 的 `[workspace.package].version`，两个
平台 crate 以 `version.workspace = true` 共享。

# v0.2.0

# 2026101518480701
# 2026年10月15日18点48分07秒 第1次修改

1.从 foims 主仓拆出为独立工作空间（与主程序仅网络通信，版本解除绑定）：
  - `foims-agent-core`：平台无关层——指标模型（MetricFamily）、采集器框架
    （Collector trait/超时冷却/scrape + ScrapeMetrics 四字段注入，解决
    node_/windows_exporter_ 两套抓取指标名与 help 文案差异）、上报
    transport 全套（h3 mTLS 交换/退避/断网缓存/证书续期检查）与
    `Platform` trait（version/machine_id/collect_frame/persist_renewed_material
    四钩子，Reporter<P: Platform> 泛型复用全部上报调度）；
  - `foims-protocol`：上报协议类型与 x509 解析（与主仓 foims-common 的
    report.rs/x509.rs 为受控双副本，修改必须双侧同步）；
  - `foims-agent`：Linux 平台 33 个 node_exporter 对齐采集器 + LinuxPlatform
    （/etc/machine-id、proc 统计、传感器、续期落盘 0644/0600 原子替换）；
  - `foims-agent-windows`：windows_exporter 默认启用 8 采集器（cpu/logical_
    disk/memory/net/os/physical_disk/service/system）Go→Rust 移植，指标名/
    help/标签逐字对齐（windows_exporter_collector_duration_seconds 等）；
    FFI 集中 ffi.rs（PDH/注册表/SCM/系统信息/卷信息/进程时间，模块级
    allow(unsafe_code) 唯一豁免点），os 采集器走注册表 + GetTickCount64 +
    GlobalMemoryStatusEx 避免 WMI，service 走 SCM API + 进程创建时刻；
  - workspace lints：`unsafe_code = "deny"`（可被 ffi 模块局部 allow 覆盖）
    + clippy 护栏集。
2.交叉编译矩阵：tier1/2 五 musl 目标（gcc 后端注入 musl 交叉 C 编译器 /
  AGENT_BACKEND=zigbuild 走 zig cc）+ 新增 x86_64-pc-windows-gnu（mingw-w64
  交叉 C 编译器或 zigbuild），产物统一命名 foims-agent（windows 目标
  cargo 自动追加 .exe，经 [[bin]] name = "foims-agent"）；windows 0.62
  适配要点：BOOL 移至 windows-core、QueryServiceConfigW/GetProcessTimes
  等 BOOL 型 API 返回 Result<()>、ENUM_SERVICE_STATUS_PROCESSW/
  QUERY_SERVICE_CONFIGW 带 W 后缀、dwCurrentState/dwStartType 为新类型
  需 .0 取值。manifest.json version 语义 = agent 版本（版本门控已移除）。
3.验证：cargo test --workspace 173 测试全绿、clippy --release -D warnings
  与 fmt --check 通过；x86_64-pc-windows-gnu 交叉编译实测产出 PE32+ 二进制
  （11.6 MiB，--only 与全量构建均验证归集与 SHA256SUMS/manifest 生成）。

# v0.2.1

# 2026101523493401
# 2026年10月15日23点49分34秒 第1次修改

1.清理 HTTP/3 上报可行性 demo 残留：删除 examples/h3_demo.rs（server/client
  双子命令验证性代码，假设已由 foims-agent-core transport 与主仓
  foims-agent-service report_server 正式实现承载）及仅服务该 demo 的
  dev-dependencies（bytes/h3/h3-quinn/http/quinn/rustls/tokio，正式链路依赖
  均在 foims-agent-core [dependencies]），同步修正 reporter.rs 与
  report_smoke.rs 中对 h3_demo / gen-h3-demo-certs.sh 的注释引用；
  report_smoke 冒烟示例（走正式 Reporter）保留。

# v0.3.0

# 2026101601004501
# 2026年10月16日01点00分45秒 第1次修改

1.采集/上报解耦 + 批量上报（大规模主机部署负载优化，模块级 x+1）：
  - 采集与上报解耦：新增 collect_interval_secs 采集间隔（默认 5s，
    clamp 1-60），ConfigFile/ReporterConfig 扩展该字段（build 四参签名
    不变、缺省 5）；独立采集任务周期采帧入内存队列，主循环仍按
    report_interval 批量出队上报，采集频率不再受上报间隔拖累；
  - FrameQueue 内存帧队列（上限 120 帧 / 8MiB，超限弃最旧，dropped
    计数随响应回执观测）；上报失败整批放回并按时间序对半拆分逐级
    降批量（最终退化为单帧），兼容旧服务端与 413 容量拒绝；
  - H3Transport QUIC 连接复用：空闲 ≥120s 自动关闭重建，复用失败重建
    重试一次；证书续期成功后立即关闭连接使新证书生效；删除断网磁盘
    缓存重放（PENDING_CACHE_CAP/cache_push/replay_pending）；
  - report_once（--once）保持单帧单报不变；
2.foims-protocol 受控双副本同步：AgentReportBatch{frames, dropped}
  批量帧协议（主仓 foims-common report.rs 同步，roundtrip 测试双侧覆盖）；
3.验证：cargo test --workspace 178 测试全绿，clippy --release
  -D warnings 与 fmt 通过。

# v0.4.0

# 2026101608304901
# 2026年10月16日08点30分49秒 第1次修改

1.分发模型重构（构建链，agent 程序代码零改动）：build-agent.sh 新增 OS
  系统包组装——Linux 每目标 deb（dpkg-deb）+ rpm（rpmbuild，_dbpath 指向
  临时库免系统 rpmdb 依赖），Windows zip（exe + README.txt），产物归集
  dist/packages/ 并生成 SHA256SUMS；systemd unit（foims-agent.service）与
  Windows 说明为 deploy/agent/ 包内物料唯一来源；删 manifest.json 与
  install.sh 归集（服务端动态组二进制链路已移除，无消费者）；产物结构
  dist/agents/ → dist/bin/（二进制原料）+ dist/packages/（系统包）；
2.程序包/配置包解耦语义：程序包只含二进制 + systemd unit + 空配置目录
  /etc/foims-agent/（postinst 检测服务端下发的配置包已就位即 enable +
  try-restart，prerm 卸载时 stop/disable）；配置由主程序 /api/agents/
  config-package 现场组包安装到同目录；
3.CI：ci.yml build 任务独立跑 build-agent.sh（AGENT_BACKEND=zigbuild），
  release 任务改下载 build 任务 artifact 直传发布页，不再重复编译。

# 2026年10月16日19点48分06秒 第1次修改

1.发布产物补齐裸 exe（构建链，agent 程序代码零改动）：Windows 目标在
  zip 之外新增独立发布形态 foims-agent-<版本>-windows-amd64.exe（与 zip
  同一二进制 install 拷贝，免解压直接下载运行），纳入 SHA256SUMS 校验和；
  CI release 上传 glob 为 dist/packages/* 自动覆盖无需改动；版本
  0.4.0→0.4.1。

# 2026年10月16日20点29分50秒 第1次修改

1.Windows 发布产物收敛为裸 exe（构建链，agent 程序代码零改动）：删除
  zip 包装形态（exe + README.txt），部署说明 README-windows.txt 保留于
  仓库 deploy/agent/ 不再进包；组包工具链不再依赖 zip（NEED_WINDOWS
  的 zip 命令检查删除）；版本 0.4.1→0.4.2。
2.修复多架构 rpm 静默丢失（产物清点时暴露的既有缺陷）：rpm 6 起可构建
  架构收窄到宿主同族（compatible build archs 仅 x86_64 系），spec 显式
  BuildArch 对异族架构直接报 No compatible architectures found for
  build，aarch64/i686/armhfp/armv7hl 四个 rpm 从未产出；spec 删
  BuildArch 行（包架构由 --target 决定，实测包元数据 Architecture 正确）；
  package_linux_rpm 的 rpmbuild/mv 失败显式 return 1（函数经 if 条件
  上下文调用时 set -e 失效，末尾 rm -rf 成功曾把失败掩盖为返回 0）；
  全量重跑验证 5 架构 rpm 全部产出且 SHA256SUMS 校验通过。

# 2026年10月16日21点09分57秒 第2次修改

1.删除 arm-unknown-linux-musleabihf（ARMv6）构建目标：deb_arch_of 曾将
  它与 armv7 目标折叠映射到同一 armhf 架构名，deb 包文件名相同互相
  覆盖；且 deb/rpm 生态无 armv6 形态（Debian armhf 与 RHEL armhfp 均
  为 armv7 语义），armv7 二进制在 armv6 设备上无法运行，armv6 包无
  正确分发渠道；构建矩阵收缩为 4 Linux（x86_64/aarch64/i686/armv7）
  + 1 Windows，deb_arch_of/rpm_arch_of/cc_for_target 同步清理对应
  armv6 分支（armhfp 映射随之删除）。

# v0.5.0

# 2026101623033201
# 2026年10月16日23点03分32秒 第1次修改

1.Windows exe 产物改造为 Windows SCM 服务程序（模块级 x+1）：
  - 新增 foims-agent-windows service 模块（--service）：SCM 状态机
    START_PENDING → RUNNING（接受 STOP）→ STOP_PENDING → STOPPED，
    StartServiceCtrlDispatcherW + RegisterServiceCtrlHandlerExW，
    上报循环复用 Reporter 常驻 task（Reporter::run 无停止协议，
    STOP 时 abort + shutdown_timeout(3s) 兜底回收）；配置加载失败
    服务空转等停止指令（错误由日志暴露），避免反复重启；
  - install.cmd/uninstall.cmd（deploy/agent/ 包内物料）：install.cmd
    经 sc.exe 注册服务（binPath 内层 \" 转义 + cert-dir 尾加点防
    \" 解析）、写 description、stop+delete 前置保证幂等重装；
    README-windows.txt 重写为 zip 服务模式安装流程；
  - build-agent.sh Windows 产物回归 zip（exe + install.cmd +
    uninstall.cmd + README.txt 平铺），组包工具链重新依赖 zip；
  - console 模式（--once/--format/--listen）保留不变，调试用。
2.验证：cargo test --workspace 全绿（Linux 宿主 parse_cli 用例）、
  x86_64-pc-windows-gnu 交叉编译 + 组包实测（zip 形态 + SHA256SUMS）。

# v0.5.1

# 2026102619350001
# 2026年10月26日19点35分00秒 第1次修改

1.修复 CI 检出下 watchdog fixture 测试失败（bug 修复级 z+1）：
  - 根因：git 不跟踪空目录，fixture 中故意留空的「无属性设备」目录
    watchdog1 从未入库，CI 检出后仅剩 watchdog0，
    test_collect_matches_fixture 断言 info 样本数 2 落空（left 1 right 2）；
    本机因目录存在而全绿，掩盖断链；
  - 修复：watchdog1/ 放置 .gitkeep 占位使目录可入库（内容为说明文字，
    非属性文件名，不会被属性读取逻辑命中）；watchdog 采集器目录遍历
    新增点文件过滤（sysfs 真实设备名均为 watchdog<N>，无点前缀形态，
    .gitkeep 不会成为假设备样本）；.gitkeep 注释标明勿在此放置属性文件；
  - 另：全量扫描确认 fixture 中仅此一处空目录，无同类隐患。
2.验证：cargo test --release 全量 179 passed 全绿（含 watchdog fixture 用例）；
  本地模拟 CI 检出（暂移 fixture 复现失败→恢复后全绿）确认根因闭环。

# v0.5.2

# 2026102619533801
# 2026年10月26日19点53分38秒 第1次修改

1.测试代码 unwrap/expect 告警清零（z+1，纯测试重构）：
  - 现状：13 处存量告警全在 foims-agent crate 的 7 个采集器测试模块
    （cpu/diskstats/filefd/filesystem/loadavg/netdev/stat）——11 处
    unwrap_err() + 2 处 unwrap()，本工作空间 [workspace.lints] 把
    unwrap_used/expect_used 定为 warn，故 -D warnings 下必红灯；
  - 修法取舍：不用主仓式 crate 根 #![cfg_attr(test, allow(...))] 豁免。实测本
    工作空间单测主流写法已占绝对优势（unwrap_or_else 203 处、matches! 50 处），
    这 13 处才是偏离者；加豁免等于引入第二套机制并反向鼓励后续继续写
    unwrap，故按同源风格改写：错误断言塌缩为既有的
    `assert!(matches!(解析调用, Err(CollectorError::Parse { .. })))` 单式
    （同文件内已存在该形状，并去掉临时 error 绑定），成功取值改用
    `unwrap_or_else(|error| panic!("...：{error}"))` 写法；断言语义逐处等价
    （原路径：unwrap_err 遇到 Ok 即 panic / 现路径：matches! 不中即 assert 失败）；
  - Cargo.toml 护栏注释补写该口径（为何不设测试豁免），配合主仓 CI 新增的
    agent clippy 门防回归。
2.验证：grep 确认全工作空间 unwrap()/unwrap_err()/expect() 残留为 0；
  cargo fmt --check 通过；cargo clippy --release --workspace --all-targets -- -D warnings
  0 告警（含 windows crate 在 Linux 宿主上的 cfg 外目标）；cargo test --release 全量 179 passed。

# v0.5.4

# 2026110117551801
# 2026年11月1日17点55分18秒 第1次修改

1.CI 随仓库拆分正式独立（构建链变更，agent 程序代码零改动）：主仓 ci.yml/release.yml 的 agent-build 任务（fmt/clippy/本机单测 + zig 0.13.0 与 llvm-mingw 20261020 交叉工具链 + AGENT_BACKEND=zigbuild build-agent.sh 多平台组包）整体迁入本仓自建的 .github/workflows/ci.yml（push 全分支 + tag v* 触发，tag 触发时产物随 CI 发布至本仓 Release）与 release.yml（workflow_dispatch 手动发布，prepare 任务从根 Cargo.toml [workspace.package] version 推导 v<version> tag 并校验指向，该 version 与 build-agent.sh 产物命名同源）。补记：v0.5.3（实时秒级采集上报推送通道的版本联动）由主仓 dev_version.md v0.54.0 条目承载，本仓记录此前漏登，自本条起恢复连续。验证：workflow 与原主仓 agent-build 任务逐步对齐复核；cargo 程序代码零改动，仅记录 z+1，Cargo.toml 0.5.3 不联动



# v0.5.5

# 2026110220300001
# 2026年11月2日20点30分00秒 第1次修改

1.修复 filesystem 采集器挂载点排除口径与 SNMP 侧不一致（功能 bug 修复，y 段
  +1）：/run/credentials/.+ 排除扩为 /run 整树——/run 及其子树（/run/user/*、
  /run/lock 等）均为 tmpfs 内存盘挂载，计入 node_filesystem_size_bytes 会使
  主机监控磁盘列表混入内存盘噪音、磁盘容量热列被内存盘行干扰，且与 SNMP 侧
  （主仓 metrics.rs is_excluded_mount 同口径四子树）同机对不上；node_exporter
  基础排除规则不变，/run 整树为本项目扩展（模块头注释注明）。验证：
  cargo fmt、clippy、filesystem 7 单测（is_excluded_mountpoint 新增 /run 整树
  与 /runtime 非整词断言）通过；主仓侧关联版本记录见其 dev_version.md v0.55.0。
  Cargo.toml 0.5.3→0.5.4 联动（v0.5.4 为 z+1 不联动记录，实际版本自此条起递增）

# v0.8.0

# 2026110413182801
# 2026年11月4日13点18分28秒 第1次修改

1.上报响应控制面退役（协议变更 y+1，与服务端 v0.80.0 同步落地）：
  - 协议受控副本 foims-protocol/src/report.rs 删除 ReportResponse
    （report_interval / collectors / latest_version 三个字段均无消费方，
    属旧协议兼容残留）；服务端上报响应改为空 JSON 对象；
  - foims-agent-core 上报链路不再解析响应体：send_batch/send_report/
    report_once 返回 Result<()>，成功以 HTTP 200 判定；删除
    log_response 控制面日志与 ReportResponse 导入；
  - --once 与冒烟客户端日志不再打印响应字段（report_smoke 不再回显
    响应 JSON）。
2.部署顺序：新版 agent 对旧服务端兼容（旧服务端仍回 ReportResponse JSON，
  新版 agent 不解析响应体），建议先升级 agent 再升级服务端；旧版 agent
  对新服务端会因响应缺字段反序列化失败而持续重试，需随后升级。
3.验证：cargo fmt 通过；cargo clippy --workspace --all-targets -D warnings
  0 告警；cargo test --workspace 全绿。Cargo.toml 0.7.0→0.8.0。

# v0.7.1

# 2026110213375701
# 2026年11月2日13点37分57秒 第1次修改

1.修复宿主 workspace 全量构建的产物名冲突（cargo#6313）：windows crate
  移除显式 [[bin]]（bin 名默认取包名 foims-agent-windows），不再与 Linux
  版 bin 同名 foims-agent——此前 cargo build --release 会对
  target/release/foims-agent 报 output filename collision 警告（未来将
  变硬错误）；两平台 bin 名与各自 main.rs USAGE 文案天然一致。
2.build-agent.sh 同步：product_name_of 的 windows 分支改为
  foims-agent-windows.exe（归集原料名），Windows zip 组包仍统一改名
  foims-agent.exe（install.cmd/服务名/对外产物名不变）；脚本头注释同步。
3.验证：cargo build --release 全 workspace 无冲突警告，四成员产物齐全
  （foims-agent / foims-agent-windows 双 bin + 两 lib）。

# v0.7.0

# 2026110209520701
# 2026年11月2日09点52分07秒 第1次修改

1.上报形态改为逐帧实时（业务变更 y+1，与服务端 v0.59.0 同步落地）：
  - 稳态上报节奏：采集任务每 collect_interval_secs 产帧，上报循环同拍取
    队列即发——常态单帧直发 `POST /agent/v1/report` 逐帧入库（快照与历史
    与服务端同步到秒级）；积压（采集耗时波动、断网缓冲）时自动多帧组批
    一次发送，AgentReportBatch 仅作断网补传载体（120 帧 / 8MiB 上限与
    对半拆分重试口径不变）；
  - 移除实时旁路通道：删除 RealtimeChannel / REALTIME_PATH /
    REALTIME_CHANNEL_CAP 与每帧 best-effort 直发（服务端 /agent/v1/realtime
    已同版本移除），每机由两条 QUIC 常驻连接收敛为一条；
  - 上报间隔协议面废止：ReporterConfig 删 interval_secs 与服务端下发
    report_interval 消费逻辑（apply_interval/clamp_interval/MIN/MAX/
    DEFAULT 间隔常量删除），agent.toml 遗留 report_interval_secs 键由
    反序列化忽略；退避基准改为采集节拍，删除 ±10% 抖动及其 rand 依赖
    （foims-agent-core）；
  - --once 日志不再打印 latest_version（服务端已废止 client 版本通告，
    响应 latest_version 恒空，字段为旧协议兼容保留）；
  - 协议受控副本 foims-protocol/src/report.rs 注释与主仓 foims-common
    同步（ReportResponse 语义注明废止口径），测试同步清理
    （test_config_from_toml 去 interval 断言；jitter/clamp_interval 用例
    随实现删除）。
2.验证：cargo fmt 通过；cargo clippy --workspace --all-targets -D warnings
  0 告警；cargo test -p foims-agent-core 11 项全绿。Cargo.toml 0.6.0→0.7.0。

# v0.6.0

# 2026110204373201
# 2026年11月2日04点37分32秒 第1次修改

1.Linux 默认采集器补全（功能新增，y 段 +1）：对齐 node_exporter 默认启用集
  （registerCollector defaultEnabled 判定，排除平台专属 exec/netisr/partition
  与默认禁用 swap/processes），新增 14 个采集器（crates/foims-agent/src/
  collectors/，全部纯 Rust 文件读取，crate 内零 unsafe、零新增依赖、零 FFI）：
  - tapestats（sysfs scsi_tape stats，ns 换算）、fibrechannel（sysfs fc_host
    info+counter，u64::MAX 跳过）、mdadm（/proc/mdstat）、ipvs
    （/proc/net/ip_vs 十六进制解析）；
  - powersupplyclass（sysfs power_supply 50 族）、dmmultipath
    （/sys/block/dm-*，slave device/state running|live=active）、infiniband
    （sysfs 64 族）、nvme（sysfs 6 族）；
  - nfs/nfsd（/proc/net/rpc/{nfs,nfsd}，nfsd 复用 nfs 解析函数；对齐 Go
    parseClientV4Stats 赋值序与 ClientV4Stats 声明序在 LayoutGet/
    GetDeviceInfo 的错位，e2e golden 验证 LayoutGet=90、GetDeviceInfo=1）、
    netclass（默认路径纯 sysfs，上游 rtnetlink 为默认关闭 flag 不移植；
    flags&1 推导 adminstate）；
  - xfs（/proc/fs/xfs/stat 39 族）、btrfs（sys/fs/btrfs 11 族，Go 侧 ioctl
    设备统计分支依赖 FFI 不移植、恒走 ioctl 失败回退分支）、zfs
    （proc/spl/kstat/zfs 278 族，rw 行列序反转对齐、dataset 名保留行内空格）；
  - timex 不移植：需 adjtimex 系统调用，无法纯 Rust 文件读取实现，按本仓
    「不引入 libc/FFI」约束排除（默认启用集唯一未移植项）；
  - fixtures 自持入库（提取自上游 sys.ttar 白名单子树 + no-clobber 合并，
    修复 ttar 无尾换行内容的 "EOF" 粘连污染 19 个文件）；默认集 32→46。
2.构建矩阵对齐 node_exporter/.github（build-agent.sh）：tier3 架构集对齐
  .promu.yml 的 linux 交叉矩阵，ppc 由 32 位 powerpc（deb/rpm 渠道已无主流
  发行版，与 armv6 同理裁剪）换为 64 位大端 powerpc64（rpm ppc64 标准架构），
  deb_arch_of/rpm_arch_of 映射同步；armv5/armv6 裁剪依据与 darwin/netbsd/
  openbsd 不产出的原因（对应平台采集器集合未移植，出二进制无采集内容）
  注释写明。
3.第三方归属：新增 THIRD_PARTY_NOTICES.md（node_exporter Apache-2.0 全文 +
  原始 NOTICE 原文、windows_exporter MIT 全文，注明快照版本/移植范围/文件
  级溯源方式，满足 Apache-2.0 第 4 条归属要求）；README 补充项目定位与
  归属指引。
4.验证：cargo fmt --check 通过；cargo clippy --workspace --all-targets
  -D warnings 0 告警；cargo test --workspace 全绿（各 crate 合计 231 项，
  含 14 采集器新增 fixture/golden 用例）。Cargo.toml 0.5.4→0.6.0 联动。
