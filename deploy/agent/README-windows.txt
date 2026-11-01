FOIMS Agent (Windows)
=====================

安装步骤（服务模式，需管理员权限）：

1. 从 FOIMS 服务端「主机监控」页下载「配置包（zip）」并解压，
   得到四个配置文件：
     agent.toml   上报配置（server_addr/token/采集与上报间隔）
     ca.pem       站点 CA 证书（mTLS 信任锚）
     client.pem   客户端证书
     client.key   客户端私钥（敏感物料，请勿泄露）

2. 将本 zip 包内容（foims-agent.exe、install.cmd、uninstall.cmd、
   README.txt）与上述四个文件解压到同一目录，例如 C:\foims-agent\。

3. 双击（或以管理员身份在命令行）运行 install.cmd：脚本经 sc.exe
   将 agent 注册为 Windows 服务（服务名 foims-agent，自动启动），
   注册成功后立即拉起。

4. 验证：服务管理器（services.msc）中查看 foims-agent 是否处于
   「正在运行」；服务端「主机监控」页确认主机上线。

卸载：
   以管理员身份运行 uninstall.cmd（服务停止并删除；配置与证书
   文件保留在本目录，如需彻底清理请手动删除）。

故障排查：
   - 服务启动失败：核对 agent.toml 是否与 ca.pem/client.pem/
     client.key 同目录，事件查看器「Windows 日志 → 应用程序」
     中查看 foims-agent 来源的错误。
   - 配置更新：修改 agent.toml 后重启服务
     （sc.exe stop foims-agent && sc.exe start foims-agent）。

注意：agent.toml 中的 token 与 client.key 属敏感物料，请妥善保管
（目录权限建议仅管理员可读）。
