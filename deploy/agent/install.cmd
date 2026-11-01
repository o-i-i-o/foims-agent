@echo off
chcp 65001 >nul
rem FOIMS Agent 服务安装脚本（sc.exe；需以管理员身份运行）

net session >nul 2>&1
if errorlevel 1 (
    echo 错误：请以管理员身份运行本脚本。
    pause
    exit /b 1
)

if not exist "%~dp0foims-agent.exe" (
    echo 错误：未找到 foims-agent.exe（请保持脚本与 exe 同目录）。
    pause
    exit /b 1
)
if not exist "%~dp0agent.toml" (
    echo 错误：未找到 agent.toml（请先从 FOIMS 服务端下载配置包并解压到本目录）。
    pause
    exit /b 1
)

rem 重复安装时先移除旧服务（停止 + 删除，幂等重装）
sc.exe stop foims-agent >nul 2>&1
sc.exe delete foims-agent >nul 2>&1

rem binPath 内层引号以 \" 转义；cert-dir 取 "%~dp0."（尾加点）防止
rem 路径末尾反斜杠被解析为转义引号
sc.exe create foims-agent binPath= "\"%~dp0foims-agent.exe\" --service --config \"%~dp0agent.toml\" --cert-dir \"%~dp0.\"" start= auto
if errorlevel 1 (
    echo 错误：服务注册失败（sc.exe create 返回 %errorlevel%）。
    pause
    exit /b 1
)
sc.exe description foims-agent "FOIMS Agent 指标采集与上报服务（HTTP/3 mTLS）"
sc.exe start foims-agent
if errorlevel 1 (
    echo 服务已注册但启动失败，请用 sc.exe query foims-agent 查看状态。
    pause
    exit /b 1
)
echo 安装完成：foims-agent 已注册为 Windows 服务（自动启动）并已拉起。
pause
