# workbuddy2api

把 **WorkBuddy / CodeBuddy（腾讯代码助手）** 的桌面端登录态，转成你本机可直接使用的 **OpenAI / Anthropic 兼容 API**。

适用场景：

- 用 **Codex CLI** 走 `/v1/responses`
- 用 **Claude Code / CC Switch** 走 `/v1/messages`
- 用 **Cherry Studio / ZCode / LobeChat / NextChat / Open WebUI** 走 `/v1/chat/completions`

> **本仓库（workbuddy-switch-plus）的改造**：账号来源改为**直读并热加载
> `~/.wb-switch-plus/accounts.json`**（WB-Switch-Plus 的账号库，增删账号无需重启服务），
> 并移植了多密钥分发（IP/模型白名单 + 额度）与多用户鉴权；管理界面并入
> WB-Switch-Plus 的 React SPA，也可用自带静态后台 `/admin/`。
> 支持打包成单文件 exe：`python build-exe.py` → `dist/wb-reverse-proxy.exe`，双击即用。
> 细节见 **[PORTING.md](./PORTING.md)**。

[English](#english) · [中文](#中文)

---

## 中文

### 这是什么

`workbuddy2api` 是一个本地协议转换器。它会读取你已经登录好的 WorkBuddy / CodeBuddy 桌面端凭据，转发到腾讯后端 `copilot.tencent.com`，然后在本地暴露这些接口：

- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/messages`
- `GET /v1/models`
- `GET /health`

它不负责登录，不模拟桌面端，也不替你执行工具。它只做三件事：

1. 读取本机登录态并注入鉴权头
2. 在 OpenAI / Anthropic 协议和腾讯后端协议之间转换
3. 对 `Codex CLI` 这类长上下文 agent 请求做后端友好的压缩投影

> 命名说明：项目对外名称现在叫 `workbuddy2api`。代码里仍保留部分历史命名，比如 `codebuddy2openai`、`CODEBUDDY2OPENAI_*`，目的是兼容旧配置和环境变量。
> 另外，GitHub 仓库路径当前也可能仍沿用 `codebuddy2openai`，这是仓库路径与项目展示名尚未完全统一，不影响使用。

### 你能用它做什么

- 把 WorkBuddy 订阅复用到 OpenAI 兼容客户端
- 让 Codex CLI 直接接腾讯后端，而不是只接 OpenAI 官方
- 让 Claude Code 通过 CC Switch 复用 WorkBuddy 支持的模型
- 保留原生 `tools` / `tool_calls` / 流式 SSE / 多轮工具调用

### 当前支持

| 客户端 / 协议 | 接口 | 当前状态 |
|------|------|------|
| OpenAI Chat Completions | `/v1/chat/completions` | 已支持 |
| OpenAI Responses | `/v1/responses` | 已支持，适配 Codex CLI |
| Anthropic Messages | `/v1/messages` | 已支持，适配 Claude Code / CC Switch |
| OpenAI Models | `/v1/models` | 已支持 |
| Health Check | `/health` | 已支持 |

---

## 3 分钟上手

### 1. 前置条件

你需要先满足这 3 个条件：

1. 本机已经安装并登录 **WorkBuddy / CodeBuddy** 桌面端
2. 本机有 **Python 3.10+**（Docker 使用 Python 3.12）
3. 已安装依赖 `fastapi`、`uvicorn`、`httpx`、`cryptography`

默认会在这些位置寻找登录态：

- macOS: `~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/*.info`
- Windows: `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\*.info`
- Linux: `~/.local/share/CodeBuddyExtension/Data/Public/auth/*.info`

### 2. 安装依赖

推荐用 `uv`：

```bash
git clone https://github.com/ShouZhuo0413/codebuddy2openai.git workbuddy2api
cd workbuddy2api

uv venv
uv pip install -r requirements.lock.txt
```

也可以用虚拟环境：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
```

`requirements.lock.txt` 锁定直接依赖和间接依赖的版本，推荐用于稳定安装；Docker 构建也使用它。文件保留 Python 版本及平台条件，例如 Windows 不安装 `uvloop`。`requirements.txt` 保留未锁定的直接依赖，主动尝试新版时可运行 `uv pip install --upgrade -r requirements.txt`。

维护者更新锁文件后需重新安装并运行测试：

```bash
uv pip compile --universal --python-version 3.10 --no-strip-extras --no-annotate --upgrade requirements.txt -o requirements.lock.txt
uv pip sync requirements.lock.txt
uv pip install -c requirements.lock.txt pytest
uv run python -m pytest tests/
```

> 注意：无论是启动服务，还是执行 `python3 -m core.converter --help`，都必须先装依赖。

### 3. 启动

最常用的启动方式：

```bash
uv run python -m core.converter --desensitize --log converter.log
```

或：

```bash
python3 -m core.converter --desensitize --log converter.log
```

看到监听 `http://127.0.0.1:8787` 就说明已经起来了。

### 4. 快速自检

```bash
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/v1/models
```

如果这两条能通，说明本地服务、登录态、基本路由都没问题。

---

## 客户端接入

### Codex CLI

这是当前最推荐的接法。Codex CLI 走的是 `/v1/responses`，而不是 `/v1/chat/completions`。

推荐启动命令：

```bash
uv run python -m core.converter --desensitize --log converter.log
```

把下面配置合并到 `~/.codex/config.toml`：

```toml
[model_providers.workbuddy]
name = "WorkBuddy (via local converter)"
base_url = "http://127.0.0.1:8787/v1"
wire_api = "responses"
env_key = "CODEBUDDY2OPENAI_KEY"

[profiles.workbuddy]
model = "glm-5.2"
model_provider = "workbuddy"
```

设置一个占位环境变量：

```bash
export CODEBUDDY2OPENAI_KEY=any-value
```

启动：

```bash
codex --profile workbuddy "你的任务描述"
```

补充说明：

- 推荐保留 `--desensitize`
- 当前 `/v1/responses` 默认已经会做投影压缩
- 如果你想尽量保留原始 system prompt，可试 `--desensitize --no-compact`
- `--desensitize --no-compact` 下若仍命中审核，当前实现会自动退回紧凑模式重试一次

### Claude Code / CC Switch

Claude Code 不走 OpenAI 协议，而是走 Anthropic Messages。

推荐启动命令：

```bash
uv run python -m core.converter --desensitize --log converter.log
```

在 CC Switch 里配置：

```json
{
  "DeepSeek-V4-Pro": {
    "base_url": "http://127.0.0.1:8787/v1/messages",
    "api_key": "",
    "model": "deepseek-v4-pro"
  }
}
```

注意：

- 模型名必须填写腾讯后端支持的真实模型名
- 不做 Anthropic 模型名到腾讯模型名的自动映射
- Claude Code 场景强烈建议开启 `--desensitize`

### 其他 OpenAI 兼容客户端

适用于：

- Cherry Studio
- ZCode
- LobeChat
- NextChat
- Open WebUI
- 自己写的 OpenAI SDK 客户端

配置方式：

- Base URL: `http://127.0.0.1:8787/v1`
- API Key: 留空，或填你启动时设置的 `--api-key`
- 模型名: `glm-5.2` / `deepseek-v4-pro` / `kimi-k2.7` / `auto` 等

---

## 常用命令

### 基本启动

```bash
python3 -m core.converter
python3 -m core.converter --desensitize
python3 -m core.converter --desensitize --log converter.log
python3 -m core.converter --api-key mysecret
python3 -m core.converter --port 9000
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|------|------|
| `--host` | `127.0.0.1` | 监听地址 |
| `--port` | `8787` | 监听端口 |
| `--api-key` | 无 | 给本地客户端加一层鉴权 |
| `--log` | 无 | 记录请求与响应日志 |
| `--desensitize` | 关 | 压缩运行时提示、去掉 tool description、零宽脱敏高风险关键词 |
| `--no-compact` | 关 | 配合 `--desensitize` 使用，保留更完整的原始 system prompt |
| `--skip-check` | 否 | 跳过启动预检 |

### curl 示例

```bash
curl http://127.0.0.1:8787/v1/models

curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5.2","messages":[{"role":"user","content":"你好"}]}'

curl -N http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5.2","stream":true,"messages":[{"role":"user","content":"数1到5"}]}'
```

---

## 日志与排障

### 推荐启动方式

```bash
uv run python -m core.converter --desensitize --log converter.log
```

### 日志里能看到什么

每次请求都会带一个唯一 ID，常见日志包括：

- `REQUEST BODY`
- `RESPONSES → CHAT BODY`
- `RESPONSES PROJECTION`
- `RESPONSE BODY`
- `RESPONSE RAW SSE`
- `⚠️内容审核拦截`

其中 `RESPONSES PROJECTION` 会告诉你：

- 投影前后消息数
- 投影前后字符数
- tool schema 压缩量
- 是否丢掉了 harness 消息
- 是否保留了 anchor user

### 最常见问题

#### 找不到登录文件

说明桌面端没登录，或者登录目录不在默认路径。先确认桌面端已经真正完成登录。

#### 401

分两种：

- 本地 401：你启用了 `--api-key`，但客户端没带同一个 key
- 后端 401：腾讯 token 失效，尝试重新打开桌面端登录

#### 400 `{"code":11128,...}`：没通过渠道校验

```
400 {"code":11128,"msg":"Illegal API invocation from an unapproved channel",
     "displayTips":{"zh":"这次调用没通过渠道校验，可能不是官方客户端发出的。"}}
```

这**不是**内容审核，也不是 token 失效，而是上游对 chat 域做的客户端渠道校验。被提升检测等级的账号会要求两样东西同时到位，缺一个就整片 11128：

1. `User-Agent` 不能是第三方反代的自报家名，也不能为空；
2. `X-Conversation-ID` / `X-Conversation-Request-ID` / `X-Conversation-Message-ID` 三枚会话头，一个都不能少。

本项目已按官方形态发这几枚头（业务代码无需改动）。如果你的环境仍报这个错，先确认跑的是不是新版本，再按需要覆盖 UA：

| 环境变量 | 作用 |
| --- | --- |
| `WB_UA` | 整串覆盖 `User-Agent`（应急/调试，不做任何拼接） |
| `WB_UA_VERSION` | 只覆盖 UA 里的版本号（默认用模块常量；账号库里记了 `clientVersion`/`appVersion` 时优先用它） |
| `WB_UA_CLI` | 只覆盖 UA 里的 CLI 段 |
| `WB_CHAT_BASE` | 覆盖 chat 主机基址（默认按账号版本自动选；国际版主机是推断值，异常时可指到 `https://www.codebuddy.ai`） |

UA 与 chat 端点都会跟着账号版本走：国际版账号自动换成 `WorkBuddy AI` 段并打到 `www.workbuddy.ai`。

国际版端点还多一条**硬要求**：首条消息必须是 `system`，否则回

```
400 {"code":11128,"msg":"first message is not system prompt"}
```

注意这跟上面的渠道校验是**同一个业务码、不同的一条规则**——看到 11128 时先看 `msg`。反代已自动处理（首个非 system 时补一条空 system，国内版不受影响），业务代码不用动。

国际版账号在池子里同样可用：额度查询与账单走 `www.workbuddy.ai`，签到体系不存在则自动跳过（不会记成失败）。

#### 第三种 11128：把 dsh 的 `@` 文件引用说明误判成非官方客户端

如果前两种都排除了，仍然报同一条 `Illegal API invocation from an unapproved channel`，先看 system 里有没有这一句：

> Relative paths resolve from the workspace root; absolute paths identify files or directories on the host.

它来自 DeepSeek Harness 的 `@deepseek-ai/dsh-file-reference` 包（`FILE_REFERENCE_PROMPT`，就是 `@文件引用` 的说明文本）。上游会把「这一句 + 前一句 `Tokens prefixed with @ are paths…`」的组合判成第三方客户端指纹。

实测（同一份 15.8K system、同一账号、同一模型）：

| 处理 | 结果 |
| --- | --- |
| 原样 | 11128（连续 2 次） |
| 删掉这句 | 200（连续 3 次） |
| 同义改写 | 200（连续 2 次） |
| 只留前半句 / 只留后半句 | 200 / 200（单句不触发，成对才触发） |

反代已自动做**同义改写**（语义不变，`@` 引用行为不受影响）。想关掉：`CODEBUDDY_NO_PROMPT_REWRITE=1`。

注意这与「提示词太长」无关：纯良性文本 30000 字符照样通过；机制是内容匹配，不是长度。

#### 响应慢

先换快一点的模型，比如 `deepseek-v4-flash`。

#### 被“敏感内容”拦截

这是腾讯后端的内容审核，不一定是用户问题本身敏感，很多时候是 agent runtime 文本触发的，比如：

- `DoS`
- `exploit`
- `credential`
- `sandbox`
- `escalation`
- 竞争品牌词
- tool description 中的安全术语

建议排查顺序：

1. 开 `--log`
2. 看同一请求 ID 下的 `REQUEST BODY` 或 `RESPONSES → CHAT BODY`
3. 如果是 Codex CLI，再看 `RESPONSES PROJECTION`
4. 开 `--desensitize`
5. 如果还不稳，再尝试 `--desensitize --no-compact`

---

## 管理后台（可选）

除原转换器外，项目附带一个中文 Web 管理后台（`admin/`），适合服务器长期运行：

- 浏览器授权添加国内 CodeBuddy / WorkBuddy 账号，无需桌面端；多账号自动轮转、冷却与积分耗尽避让
- 凭据刷新、积分余额查询、每日自动签到（默认北京时间 09:00，可配置）
- 客户端 API Key 创建与撤销、真实模型连接测试
- 概览页：请求量、完成成功率、HTTP 成功率、平均耗时与最近 100 条请求

本地启动（需先安装依赖并设置至少 20 位的管理密钥）：

```bash
export ADMIN_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(36))")
export CODEBUDDY2OPENAI_KEY=sk-wb-$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
python3 -m admin.server
```

然后访问 `http://127.0.0.1:8787/admin/`。一键 Docker 部署见下文；详细说明见 [ADMIN_README.md](ADMIN_README.md)。

> 管理后台为单进程设计，正式对外部署必须放在 HTTPS 反向代理之后（示例：`deploy/admin/nginx.conf.example`）。直接运行 `python3 -m core.converter` 的原有用法不受影响。

---

## Docker 部署

如果你更习惯用 Docker，可以直接用。

前提是把宿主机登录态目录挂进去，因为容器里拿不到桌面端 auth 文件。

### 一键部署（推荐，含管理后台）

一条命令完成密钥生成、镜像构建与启动：

```bash
bash deploy/one-click/deploy.sh
```

脚本会自动生成 `ADMIN_KEY` 与客户端 Key（保存在 `deploy/one-click/.env`，仅首次显示），随后访问 `http://127.0.0.1:8787/admin/`。改端口：编辑 `deploy/one-click/.env` 里的 `PORT` 后重跑脚本。

### docker compose（独立转换器）

先改 `deploy/standalone/docker-compose.yml` 里的 auth 挂载路径，再执行：

```bash
docker compose -f deploy/standalone/docker-compose.yml up -d --build
```

### docker run（独立转换器）

```bash
docker build -t workbuddy2api -f deploy/standalone/Dockerfile .

docker run -d --name workbuddy2api -p 8787:8787 \
  -v ~/Library/Application Support/CodeBuddyExtension/Data/Public/auth:/data/auth:ro \
  -e CODEBUDDY_AUTH_DIR=/data/auth \
  workbuddy2api
```

### 相关环境变量

| 变量 | 说明 |
|------|------|
| `CODEBUDDY_AUTH_DIR` | 指定登录态目录 |
| `CODEBUDDY2OPENAI_KEY` | 本地 API Key |
| `CODEBUDDY2OPENAI_LOG` | 日志路径 |

---

## 模型列表

当前内置默认模型列表：

`hy3`、`hy4-preview`、`kimi-k3`、`kimi-k2.8-preview`、`glm-5.3`、`glm-5.3-flash`、`glm-5.2`、`glm-5.1`、`glm-5v-turbo`、`kimi-k2.7`、`kimi-k2.6`、`kimi-k2.5`、`deepseek-v4-pro`、`deepseek-v4.1-flash`、`deepseek-v4-flash`、`minimax-m3-pay`、`hy3-preview-agent`、`auto`

> 本机装有 WorkBuddy 时优先使用其动态模型目录，上表为兜底列表。具体能不能用，取决于你的 WorkBuddy / CodeBuddy 订阅与上游状态。

---

## 项目结构

```text
workbuddy2api/
├── core/                      # 协议转换核心
│   ├── converter.py           # 主入口，FastAPI 服务（python3 -m core.converter）
│   ├── responses_adapter.py   # OpenAI Responses ↔ Chat 适配
│   ├── responses_projection.py# Codex / agent 请求投影压缩
│   ├── anthropic_adapter.py   # Anthropic Messages ↔ Chat 适配
│   └── desensitize.py         # 运行时文本压缩与零宽脱敏
├── admin/                     # 中文管理后台（可选，python3 -m admin.server）
│   ├── server.py              # 管理 API、会话与静态页面
│   ├── pool.py                # 账号池轮转、冷却、积分与签到
│   ├── browser_login.py       # 浏览器授权登录
│   ├── metrics.py             # 请求统计
│   └── static/                # 前端资源
├── deploy/                    # 部署
│   ├── standalone/            # 独立转换器（Dockerfile + compose）
│   ├── admin/                 # 管理后台（Dockerfile + compose + nginx 示例）
│   └── one-click/             # 一键式部署（deploy.sh 自动生成密钥并启动）
├── tests/                     # 单元测试（pytest）
├── codex-codebuddy.example.toml
├── README.md
└── LICENSE
```

运行测试：

```bash
python3 -m pytest tests/
```

---

## 致谢

本项目基于 [HanHan666666/codebuddy2openai](https://github.com/HanHan666666/codebuddy2openai) 的思路演进而来，感谢原作者的开源贡献。

## 免责声明

本项目仅用于个人学习与研究。与腾讯、WorkBuddy、CodeBuddy、OpenAI、Anthropic 无官方关联。请仅在你合法拥有订阅的前提下使用，并自行承担风险。

## 开源协议

[MIT](./LICENSE)

---

<a name="english"></a>
## English

`workbuddy2api` exposes your already logged-in **WorkBuddy / CodeBuddy** desktop session as local **OpenAI- and Anthropic-compatible APIs**.

Supported endpoints:

- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/messages`
- `GET /v1/models`
- `GET /health`

Recommended use cases:

- **Codex CLI** via `/v1/responses`
- **Claude Code / CC Switch** via `/v1/messages`
- **Cherry Studio / ZCode / LobeChat / Open WebUI** via `/v1/chat/completions`

### Quick Start

```bash
git clone https://github.com/ShouZhuo0413/codebuddy2openai.git workbuddy2api
cd workbuddy2api

uv venv
uv pip install -r requirements.lock.txt
uv run python -m core.converter --desensitize --log converter.log
```

Requires Python 3.10+. `requirements.lock.txt` pins runtime dependencies, including platform-specific conditions, and is also used by Docker builds. Use `requirements.txt` only when intentionally trying newer dependency versions.

Then verify:

```bash
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/v1/models
```

### Codex CLI

Use `/v1/responses` and keep `--desensitize` enabled.

```toml
[model_providers.workbuddy]
name = "WorkBuddy (via local converter)"
base_url = "http://127.0.0.1:8787/v1"
wire_api = "responses"
env_key = "CODEBUDDY2OPENAI_KEY"

[profiles.workbuddy]
model = "glm-5.2"
model_provider = "workbuddy"
```

Run:

```bash
export CODEBUDDY2OPENAI_KEY=any-value
codex --profile workbuddy "your task"
```

### Claude Code / CC Switch

Use `/v1/messages`:

```json
{
  "DeepSeek-V4-Pro": {
    "base_url": "http://127.0.0.1:8787/v1/messages",
    "api_key": "",
    "model": "deepseek-v4-pro"
  }
}
```

### Notes

- `--desensitize` is recommended for both Codex CLI and Claude Code
- `/v1/responses` already applies backend-facing projection by default
- `--desensitize --no-compact` preserves more of the original system prompt
- if that still gets review-blocked, `/v1/responses` will retry once in compact mode
- an optional Chinese web admin console (`python3 -m admin.server`, see [ADMIN_README.md](ADMIN_README.md)) adds browser-based account authorization, multi-account rotation, client API keys, daily check-in and request metrics; one-command Docker setup: `bash deploy/one-click/deploy.sh`

### CLI Options

```bash
python3 -m core.converter [--host HOST] [--port PORT] [--api-key KEY] [--log PATH] [--desensitize] [--skip-check]
```

### Disclaimer

For personal learning and research only. Not affiliated with Tencent, WorkBuddy, CodeBuddy, OpenAI, or Anthropic.

---

<sub>
Keywords: codebuddy to openai · codebuddy2openai · workbuddy api proxy · workbuddy openai adapter · codex cli workbuddy · claude code workbuddy · tencent code assistant openai compatible api
</sub>
