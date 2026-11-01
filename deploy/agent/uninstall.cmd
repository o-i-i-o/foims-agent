@echo off
chcp 65001 >nul
rem FOIMS Agent 服务卸载脚本（sc.exe；需以管理员身份运行）

net session >nul 2>&1
if errorlevel 1 (
    echo 错误：请以管理员身份运行本脚本。
    pause
    exit /b 1
)

sc.exe stop foims-agent >nul 2>&1
sc.exe delete foims-agent
if errorlevel 1 (
    echo 服务未注册或删除失败（sc.exe delete 返回 %errorlevel%）。
    pause
    exit /b 1
)
echo 卸载完成：foims-agent 服务已停止并删除。
echo 配置与证书文件（agent.toml/ca.pem/client.pem/client.key）保留在本目录，如需彻底清理请手动删除。
pause
