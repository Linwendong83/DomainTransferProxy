该项目完全是由ChatGPT-5.3-Codex生成的
用途非常狭窄
在尝试使用该项目提供的内容时，请首先确认
1.你知道SRV解析记录是什么
2.完全了解Transfer的局限性
以下是GPT生成的原始README

# Domain Transfer Proxy (Python)

一个按 **玩家访问域名** 路由的 MC 前置服务：

1. **状态查询（MOTD/在线人数/图标）** 按域名转发到对应后端，并把后端返回内容原样回传给客户端。
2. **登录后不进前置服世界**，直接通过 Minecraft 新版 `Transfer` 功能把客户端转移到对应后端服务器。

> 适配思路：面向 **1.20.5+（含配置阶段 Transfer）** 的现代客户端流程。

## 快速开始

1. 安装 Python 3.10+
2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 编辑 `config.toml` 中的域名与后端地址
4. 启动：

```bash
python server.py
```

## 配置说明

- `proxy.listen_host / listen_port`：前置服务监听地址
- `routes.<domain>.status`：该域名状态查询要去哪个后端（用于 MOTD/在线数/图标）
- `routes.<domain>.transfer`：该域名登录后要 transfer 到哪个目标地址
- 未匹配到任何 `routes.<domain>` 时：前置会直接静默断开，不返回任何内容

## 关键行为

- 读取握手中的 `Server Address` 作为玩家访问域名。
- Status 阶段：向目标后端发起一次状态查询，并将 JSON 回传。
- Login 阶段：
  - 接收 `Login Start`
  - 回 `Login Success`
  - 等待 `Login Acknowledged`
  - 下发配置阶段 `Transfer` 包（Host + Port）

## 注意事项

- 这是一个“转移网关”，不是传统全双工代理，不会持续转发游戏流量。
- 要确保客户端版本支持 `Transfer`。
- 若你网络上有 Bungee/Velocity 等，还要避免它们拦截或改写该流程。
- 若需要 TLS/防护/CDN，请在前面再加 L4/L7 组件。
