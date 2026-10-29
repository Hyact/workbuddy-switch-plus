#!/usr/bin/env python3
"""
codebuddy2openai — 把 CodeBuddy / WorkBuddy 的订阅暴露成标准 OpenAI 兼容 API。

原理（直连后端，原生 function calling）：
  - 读取本机已登录的 CodeBuddy 桌面端凭据（auth 文件里的 token / uid / enterpriseId）。
  - 直接转发到 CodeBuddy 后端 `https://copilot.tencent.com/v2/chat/completions`。
    该后端本身就是标准 OpenAI chat/completions 协议（含原生 tools / tool_calls / SSE 流式）。
  - 转换器只做两件事：①注入鉴权 header（Authorization / X-User-Id 等）
    ②在本地 /v1/* 与后端 /v2/* 之间做路径映射与透传（含 Anthropic / Chat / Responses 三种协议）。
  - token 过期时自动调 `/v2/plugin/auth/token/refresh` 刷新，并回写 auth 文件。

跨平台：自动定位 auth 目录（macOS / Windows / Linux）。
依赖：fastapi + uvicorn + httpx（pip install fastapi "uvicorn[standard]" httpx）。

用法：
  python3 converter.py                       # 默认 127.0.0.1:8787
  python3 converter.py --port 9000
  python3 converter.py --api-key mysecret    # 启用客户端鉴权
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

try:
    from .desensitize import desensitize_body
except ImportError:  # 模块缺失时降级为不脱敏

    def desensitize_body(
        body,
        roles=("system",),
        desensitize_harness_user=False,
        desensitize_tools=False,
        compact_harness=False,
        strip_tool_metadata=False,
    ):
        return body


from .anthropic_adapter import (
    AnthropicStreamConverter,
    anthropic_request_to_chat,
)
from .workbuddy_atrest_crypto import (  # issue #23：WorkBuddy 5.6.0 $wbEncrypted 信封
    decrypt_auth_field,
    encrypt_auth_field,
    is_encrypted_field,
)
from .responses_adapter import (
    ResponsesStreamConverter,
    responses_request_to_chat,
)
from .responses_projection import project_responses_chat_body
from .system_identity import filter_system_identity

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

BACKEND = "https://copilot.tencent.com"
DEFAULT_DOMAIN = "www.codebuddy.cn"
USER_AGENT = "codebuddy2openai/2.0"

# ---------------------------------------------------------------------------
# 平台相关：定位 auth 目录
# ---------------------------------------------------------------------------


def auth_dirs() -> list[Path]:
    env_dir = os.environ.get("CODEBUDDY_AUTH_DIR")
    if env_dir:
        return [Path(env_dir)]
    home = Path.home()
    plat = sys.platform
    if plat == "darwin":
        return [
            home
            / "Library"
            / "Application Support"
            / "CodeBuddyExtension"
            / "Data"
            / "Public"
            / "auth"
        ]
    if plat == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return [local / "CodeBuddyExtension" / "Data" / "Public" / "auth"]
    xdg = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return [xdg / "CodeBuddyExtension" / "Data" / "Public" / "auth"]


def find_auth_file() -> Path | None:
    for d in auth_dirs():
        if d.is_dir():
            files = list(d.glob("*.info"))
            if not files:
                continue
            # 优先用无时间戳后缀的 "当前" 文件；否则按 mtime 取最新
            current = d / "workbuddy-desktop.info"
            if current.is_file():
                return current
            return max(files, key=lambda p: p.stat().st_mtime)
    return None


# ---------------------------------------------------------------------------
# Auth 凭据管理（读 + 自动刷新 + 回写）
# ---------------------------------------------------------------------------


class CredentialManager:
    """从 auth 文件读取凭据；token 临近过期时自动刷新并回写。"""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._cached: dict | None = None
        self._mtime: float = 0.0

    def _read_raw(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _load_if_stale(self):
        """若文件 mtime 变了（外部刷新过），重新加载缓存。"""
        try:
            mt = self.path.stat().st_mtime
        except OSError:
            return
        if self._cached is None or mt != self._mtime:
            self._cached = self._read_raw()
            self._mtime = mt

    def _session(self) -> dict:
        self._load_if_stale()
        if self._cached is None:
            raise RuntimeError(f"无法读取 auth 文件：{self.path}")
        return self._cached

    def _is_expired(self) -> bool:
        s = self._session()
        expires_at = (s.get("auth") or {}).get("expiresAt") or 0
        # 提前 60s 判定过期
        return time.time() * 1000 >= (expires_at - 60_000)

    def _refresh(self):
        """调后端刷新 token，写回 auth 文件与缓存。"""
        s = self._session()
        auth = s.get("auth") or {}
        headers = self._build_headers_from(auth, s.get("account") or {})
        headers["X-Refresh-Token"] = decrypt_auth_field(auth.get("refreshToken", ""))
        headers["X-Auth-Refresh-Source"] = "plugin"
        url = f"{BACKEND}/v2/plugin/auth/token/refresh"
        try:
            with httpx.Client(timeout=15) as c:
                r = c.post(url, headers=headers, json={})
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"刷新 token 网络失败：{e}")
        if data.get("code") != 0 or not data.get("data"):
            raise RuntimeError(f"刷新 token 失败：{data.get('msg', data)}")
        new_auth = data["data"]
        if not isinstance(new_auth, dict) or not new_auth.get("accessToken"):
            raise RuntimeError("刷新响应缺少访问令牌")
        # 继承部分字段（refreshToken 兜底取解密后的旧值，避免加密信封被二次加密）
        new_auth["refreshToken"] = new_auth.get("refreshToken") or decrypt_auth_field(
            auth.get("refreshToken", "")
        )
        new_auth["domain"] = new_auth.get("domain") or auth.get("domain")
        new_auth["lastRefreshTime"] = int(time.time() * 1000)
        # 计算 expiresAt（若后端没直接给）
        if not new_auth.get("expiresAt") and new_auth.get("expiresIn"):
            new_auth["expiresAt"] = (
                int(time.time() * 1000) + new_auth["expiresIn"] * 1000
            )
        if not new_auth.get("refreshExpiresAt") and new_auth.get("refreshExpiresIn"):
            new_auth["refreshExpiresAt"] = (
                int(time.time() * 1000) + new_auth["refreshExpiresIn"] * 1000
            )
        s["auth"] = new_auth
        # issue #23：若原文件为 $wbEncrypted 加密格式，回写前必须重新加密，
        # 否则 WorkBuddy 客户端读到明文会报 integrity 错误、可能重置登录态。
        if is_encrypted_field(auth.get("accessToken")):
            new_auth["accessToken"] = encrypt_auth_field(decrypt_auth_field(new_auth["accessToken"]))
            new_auth["refreshToken"] = encrypt_auth_field(decrypt_auth_field(new_auth["refreshToken"]))
        # 原子写回
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
        self._cached = s
        self._mtime = self.path.stat().st_mtime

    def _build_headers_from(self, auth: dict, account: dict) -> dict:
        domain = auth.get("domain") or DEFAULT_DOMAIN
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {decrypt_auth_field(auth.get('accessToken', ''))}",
            "X-User-Id": account.get("uid", ""),
            "X-Enterprise-Id": account.get("enterpriseId", ""),
            "X-Tenant-Id": account.get("enterpriseId", ""),
            "X-Domain": domain,
            "User-Agent": USER_AGENT,
        }
        return h

    def get_headers(self) -> dict:
        """返回带最新 token 的后端请求 header；必要时先刷新。

        对话/业务请求合并渠道风控头（X-CodeBuddy-Request / 官方 UA / Origin
        / Referer / 设备指纹），与官方客户端对齐，避免被上游渠道校验拦截。
        token 刷新路径（_refresh）直接调 _build_headers_from，不受影响。
        """
        with self._lock:
            if self._is_expired():
                self._refresh()
            s = self._session()
            auth = s.get("auth") or {}
            account = s.get("account") or {}
            h = self._build_headers_from(auth, account)
            try:
                from admin import realm as realm_mod
                h.update(realm_mod.headers(realm_mod.realm_of(auth), uid=account.get("uid", "")))
            except ImportError:
                pass
            return h

    def summary(self) -> dict:
        s = self._session()
        auth = s.get("auth") or {}
        acct = s.get("account") or {}
        exp = auth.get("expiresAt", 0)
        return {
            "uid": acct.get("uid"),
            "nickname": acct.get("nickname"),
            "enterpriseName": acct.get("enterpriseName"),
            "token_expires_at": exp,
            "token_expired": self._is_expired(),
        }


# ---------------------------------------------------------------------------
# 模型列表
# ---------------------------------------------------------------------------

DEFAULT_MODELS = [
    "hy3",
    "hy4-preview",
    "kimi-k3",
    "kimi-k2.8-preview",
    "glm-5.3",
    "glm-5.3-flash",
    "glm-5.2",
    "glm-5.1",
    "glm-5v-turbo",
    "kimi-k2.7",
    "kimi-k2.6",
    "kimi-k2.5",
    "deepseek-v4-pro",
    "deepseek-v4.1-flash",
    "deepseek-v4-flash",
    "minimax-m3-pay",
    "hy3-preview-agent",
    "auto",
]

# 默认模型：客户端没有显式指定 model 时，反代替它选的那一个。
#
# 以前这里是上游的 `"auto"`（让后端自己挑）。二改后固定成 deepseek-v4.1-flash：
# 默认值可预测，客户端日志里看到的就是真实在跑的模型，排查对不上号的问题时
# 不用再去猜后端这次挑了什么。
#
# 注意这个值是「意图」，最终取值由 `resolve_default_model()` 按本机可用清单裁定：
# 机型/客户端版本不一样时清单会差（例如老客户端下发的配置里就没有 v4.1-flash），
# 清单里没有就退回 `auto`，避免拿着未知模型打上游整片 400。
DEFAULT_MODEL = "deepseek-v4.1-flash"

# 配置的默认模型在本机不可用时退回的值。仍然是上游的 `auto`（由后端自己挑）——
# 退回一个「本机确认存在」的具体模型同样是赌，而 auto 至少不会因为模型名错而整片失败。
FALLBACK_MODEL = "auto"

# 解析结果的短缓存。可用清单来自本机 WorkBuddy 的产品配置，每次请求都去读文件没必要；
# 又不能永久缓存——用户升了客户端之后清单会变（可能就多出了默认模型）。
_DEFAULT_MODEL_TTL_SECS = 60.0
_default_model_cache: tuple[float, str] | None = None


def resolve_default_model() -> str:
    """默认模型的最终取值：配置的 `DEFAULT_MODEL` 在本机可用清单里就用它，否则退回 `auto`。

    可用清单来自**本机 WorkBuddy** 的产品配置（优先动态缓存，其次装机快照，见
    `_find_workbuddy_product_json`），各客户端版本的内容不一样：
    这里写死一个本机没有的模型，会让所有「客户端没带 model」的请求带着未知模型
    打上游（整片 400），也会让后台测试表单选不中。
    """
    global _default_model_cache
    now = time.monotonic()
    cached = _default_model_cache
    if cached is not None and now - cached[0] < _DEFAULT_MODEL_TTL_SECS:
        return cached[1]
    try:
        models = get_available_models()
    except Exception:  # 清单读不到不该影响请求，按配置值走
        return DEFAULT_MODEL
    # 清单为空 = product.json 没找到（走了 DEFAULT_MODELS 兜底也没成），没依据可判，按配置值走。
    value = DEFAULT_MODEL if not models or DEFAULT_MODEL in models else FALLBACK_MODEL
    _default_model_cache = (now, value)
    return value


# 标识非聊天模型的 tag（需要过滤掉）
NON_CHAT_MODEL_TAGS = {
    "text-to-image",
    "image-to-image",
    "text-to-video",
}

# 客户端侧本地自定义模型的 id 前缀（WorkBuddy 里手填的别名，上游不认，见 _load_models_from_workbuddy）
CUSTOM_LOCAL_MODEL_PREFIX = "custom-local:"


# 「客户端从服务端拉取的产品配置」缓存位置：<数据目录>/cache/acc-product-config-v<N>.json。
# 安装目录里那份 `cli/product.json` 只是装机时的静态快照
# （快照 2026-10-08、49 个模型、没有 deepseek-v4.1-flash），而服务端下发的配置会把
# 新增模型带上（同一台机器上缓存 2026-10-11、55 个模型、有 deepseek-v4.1-flash）。
# 只看快照会导致「WorkBuddy 里选得到的模型，反代报未知模型 / 选不中」。
_PRODUCT_CONFIG_CACHE_SUBDIR = "cache"
_PRODUCT_CONFIG_CACHE_GLOB = "acc-product-config-v*.json"


def _find_cached_product_config() -> Path | None:
    """找客户端缓存的动态产品配置，取版本号最大的那个（同版本取 mtime 最新）。

    只扫 `<数据目录>/cache/` 这一层，不去碰 `cache/conversation-product-spill/`——
    那是按会话拆出来的副本，同一份配置会散成几百个文件，没有优先级意义。
    """
    root = os.environ.get("WORKBUDDY_DATA_DIR") or (Path.home() / ".workbuddy")
    cache_dir = Path(root) / _PRODUCT_CONFIG_CACHE_SUBDIR
    if not cache_dir.is_dir():
        return None

    candidates = [p for p in cache_dir.glob(_PRODUCT_CONFIG_CACHE_GLOB) if p.is_file()]
    if not candidates:
        return None

    def sort_key(path: Path) -> tuple[int, float]:
        match = re.search(r"-v(\d+)\.json$", path.name)
        version = int(match.group(1)) if match else 0
        return (version, path.stat().st_mtime)

    return max(candidates, key=sort_key)


def _find_workbuddy_product_json() -> Path | None:
    """
    查找本机 WorkBuddy 的产品配置文件，按「越新越优先」排序。

    优先级：
      1. `ACC_PRODUCT_CONFIG_PATH` 环境变量（客户端自己认的覆盖项，用户显式指定就听他的）
      2. `<数据目录>/cache/acc-product-config-v*.json` —— 客户端从服务端拉取的动态配置
      3. 装机时解压出来的静态快照 app.asar.unpacked/cli/product.json

    第 3 项在安装时就固定了，模型清单会随时间过期；所以它是兜底而不是首选。

    macOS: /Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/product.json
    Windows: %LOCALAPPDATA%\\Programs\\WorkBuddy\\resources\\app.asar.unpacked\\cli\\product.json
    Linux: /opt/WorkBuddy/resources/app.asar.unpacked/cli/product.json

    Returns:
        Path 对象如果找到配置文件，否则 None
    """
    env_override = os.environ.get("ACC_PRODUCT_CONFIG_PATH", "").strip()
    if env_override:
        override_path = Path(env_override)
        if override_path.is_file():
            return override_path

    cached_config = _find_cached_product_config()
    if cached_config is not None:
        return cached_config

    possible_paths = []

    if sys.platform == "darwin":  # macOS
        possible_paths.extend(
            [
                # 标准安装路径（WorkBuddy 自动解压）
                Path(
                    "/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/product.json"
                ),
                # 开发/调试：本地提取的目录
                Path.home()
                / "Desktop/workspace/opensource/codebuddy2api/workbuddy_extracted/cli/product.json",
            ]
        )
    elif sys.platform == "win32":  # Windows
        local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
        possible_paths.extend(
            [
                local_app_data
                / "Programs/WorkBuddy/resources/app.asar.unpacked/cli/product.json",
                Path(
                    "C:/Program Files/WorkBuddy/resources/app.asar.unpacked/cli/product.json"
                ),
            ]
        )
    else:  # Linux
        possible_paths.extend(
            [
                Path("/opt/WorkBuddy/resources/app.asar.unpacked/cli/product.json"),
                Path.home() / ".local/share/WorkBuddy/cli/product.json",
            ]
        )

    for path in possible_paths:
        if path.exists() and path.is_file():
            return path

    return None


def _is_chat_model_entry(entry: dict) -> bool:
    """产品配置里的一条模型是不是「可用的聊天模型」。

    过滤规则（改动前散在 `_load_models_from_workbuddy` 的循环里，抽出来是因为
    `/v1/models` 与模型中心都要用同一套判据，两边各写一遍迟早会漂）：
      1. 必须有 id
      2. 非聊天模型（text-to-image / text-to-video 等）排除
      3. vendor "tencent" 的内部模型排除（补全/跳转等内部功能）
      4. 客户端侧本地自定义模型排除（`custom-local:` 前缀 / vendor "Custom"）
      5. id 里带 completion / rewrite / jump / codewise 的排除
    """
    model_id = entry.get("id")
    if not model_id:
        return False
    if any(tag in NON_CHAT_MODEL_TAGS for tag in (entry.get("tags") or [])):
        return False
    vendor = entry.get("vendor", "")
    if vendor == "tencent":
        return False
    # 客户端侧本地自定义模型：用户在 WorkBuddy 里手填的别名，常见填法就是把 url
    # 指向反代自己（`http://127.0.0.1:8787/v1`）。它们是客户端自己解析的 id、上游不认，
    # 列进 /v1/models 只会造成自引用和 400。
    if str(model_id).startswith(CUSTOM_LOCAL_MODEL_PREFIX) or vendor == "Custom":
        return False
    name_lower = str(model_id).lower()
    if any(keyword in name_lower for keyword in ("completion", "rewrite", "jump", "codewise")):
        return False
    return True


def _read_product_config() -> dict:
    """读本机 WorkBuddy 的产品配置；读不到 / 解析失败返回空字典。"""
    product_json_path = _find_workbuddy_product_json()
    if product_json_path is None:
        return {}
    try:
        with open(product_json_path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        # 解析失败时静默降级，不影响服务启动
        print(
            f"Warning: Failed to load models from WorkBuddy product.json: {e}",
            file=sys.stderr,
        )
        return {}


def _load_model_entries_from_workbuddy() -> list[dict]:
    """可用聊天模型的**完整条目**（模型中心要上下文长度/最大输出/思考档位/单价，只留 id 不够）。"""
    data = _read_product_config()
    return [m for m in (data.get("models") or []) if isinstance(m, dict) and _is_chat_model_entry(m)]


def _load_models_from_workbuddy() -> list[str]:
    """
    从本机 WorkBuddy 的产品配置读取模型 ID 列表。

    Returns:
        模型 ID 列表，如果加载失败返回空列表
    """
    return [m["id"] for m in _load_model_entries_from_workbuddy()]


def _credit_rate(raw) -> float | None:
    """把 `credits` 字段（形如 `"x0.16 credits"` / `"x0.11"` / `""`）解析成每次调用的积分数。

    解析不出来就返回 None —— 让界面显示「—」，而不是伪装成 0（0 看起来像"免费"）。
    """
    text = str(raw or "").strip().lower()
    if not text:
        return None
    match = re.search(r"([0-9]*\.?[0-9]+)", text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _catalog_entry(entry: dict) -> dict:
    """把产品配置里的一条模型条目整理成模型中心要的形状（字段名统一成 snake_case）。

    `tags` 是「限时免费筛选」的唯一依据：上游把「限时免费」写进 tags（中文标记），
    **没有 tags 的模型一律不算免费**。不能拿 `credits` 文案去猜——那是计费说明文本，
    形态随上游改版而变；tags 是分类标记，只有它才是稳定判据。
    """
    context = entry.get("contextWindow")
    context = context if isinstance(context, dict) else {}
    supported = context.get("supportedLengths")
    reasoning = entry.get("reasoning")
    return {
        "id": entry.get("id"),
        "name": entry.get("name") or entry.get("id"),
        "vendor": entry.get("vendor") or "",
        "description": entry.get("descriptionZh") or entry.get("descriptionEn") or "",
        "context_window": context.get("defaultLength"),
        "context_window_options": [int(x) for x in supported if isinstance(x, (int, float))]
        if isinstance(supported, list) else [],
        "max_input_tokens": entry.get("maxInputTokens"),
        "max_output_tokens": entry.get("maxOutputTokens"),
        "max_allowed_size": entry.get("maxAllowedSize"),
        "credits": entry.get("credits") or "",
        "credit_rate": _credit_rate(entry.get("credits")),
        "supports_tool_call": bool(entry.get("supportsToolCall")),
        "supports_images": bool(entry.get("supportsImages")),
        "supports_reasoning": bool(entry.get("supportsReasoning")),
        "only_reasoning": bool(entry.get("onlyReasoning")),
        "reasoning_effort": reasoning.get("effort") if isinstance(reasoning, dict) else None,
        "temperature": entry.get("temperature"),
        "tags": [str(t) for t in (entry.get("tags") or []) if t],
    }


def is_free_model(entry: dict) -> bool:
    """这模型是不是「限时免费」。判据只有 tags，**没有 tags 就是收费**。

    宁可漏判也不误判：把收费模型标成免费，用户会拿它跑大活，账单出来才发现。
    """
    for tag in (entry.get("tags") or []):
        if "免费" in str(tag) or "限时免费" in str(tag) or "free" in str(tag).lower():
            return True
    return False


# ---------------------------------------------------------------------------
# 模型目录：按版本、多来源
# ---------------------------------------------------------------------------
#
# 三级来源，按「越靠前越权威」合并（同 id 时字段以靠前的为准）：
#   1. /v3/config   —— 全量，两版都有（它没有 agents 白名单）
#   2. 企业端点      —— 国内 /console/...；国际先 /v2/... 再 /console/...
#   3. 本机产品配置  —— 兜底，离线也能列出模型名
#
# 为什么不能只用产品配置：那份文件只有国内版（实测 endpoint=www.workbuddy.cn），
# 且装机快照与运行时缓存内容完全相同（date 差 6 秒、commit 一致），客户端不
# 升级就永远不变。国际版账号拿它当清单，选中的模型在国际上游不存在。

#: 两版的模型端点候选。顺序即尝试顺序。
MODEL_ENDPOINT_PATHS = {
    "global": (
        "/v2/enterprises/personal/models",
        "/console/enterprises/personal/models",
        "/v3/config",
    ),
    "cn": (
        "/console/enterprises/personal/models",
        "/v3/config",
    ),
}

#: 模型目录缓存 TTL。60 秒：够挡住界面连点刷新时的重复请求，
#: 又不至于让「上游刚上线的模型」等到下次重启才可见。
MODEL_CATALOG_TTL = 60.0

_MODEL_CATALOG_CACHE: dict = {}


def _realm_of_credential(cred) -> str:
    """按订单/凭据判断该用哪一版端点。

    凭据对象来自 `switch_store.CredentialManager`，`summary()` 里有 domain。
    拿不到就判国内版 —— 与 `realm.realm_of` 同口径（显式 realm 优先，domain 兜底）。
    """
    try:
        summary = cred.summary() if cred is not None else {}
    except Exception:  # noqa: BLE001
        summary = {}
    auth = {"realm": (summary or {}).get("realm"), "domain": (summary or {}).get("domain")}
    try:
        from admin import realm as realm_mod
        return realm_mod.realm_of(auth)
    except ImportError:
        return "cn"


def _envelope_of(resp):
    """腾讯信封 → `(code, data)`。解析不出时用状态码当 code。"""
    try:
        env = resp.json()
    except Exception:  # noqa: BLE001
        return getattr(resp, "status_code", -1), None
    if isinstance(env, dict) and "code" in env:
        try:
            return int(env.get("code", -1)), env.get("data")
        except (TypeError, ValueError):
            return -1, env.get("data")
    return getattr(resp, "status_code", -1), env


def _model_items(payload):
    """从三种上游形态里挖出模型条目列表。

    形态：`{"data": [...]}` / `{"data": {"models": [...]}}` / `{"models": [...]}`
    以及 config 形态 `{"data": {"models": {"chat": [...]}}}`（罕见但要容忍）。
    """
    node = payload
    if isinstance(node, dict):
        node = node.get("data", node)
    if isinstance(node, dict):
        node = node.get("models", node)
    if isinstance(node, dict):
        # config 风格：按分类再包一层
        for key in ("chat", "models", "list", "items"):
            if isinstance(node.get(key), list):
                return [m for m in node[key] if isinstance(m, dict)]
        return []
    if isinstance(node, list):
        return [m for m in node if isinstance(m, dict)]
    return []


def _remote_model_entries(realm: str):
    """从上游拉该版本的模型条目（同步）。

    返回 `(entries, source_url)`；一个都拿不到时返回 `([], "")`。
    走 `_proxy_kwargs()`：模型是「以该账号身份取」的，出口线路必须和对话一致，
    否则同一个账号在两条路上露出两个来源。
    """
    cred = _cred()
    headers = cred.get_headers()
    headers["Accept"] = "application/json"
    try:
        from admin import realm as realm_mod
        base = realm_mod.chat_base(realm)
        paths = MODEL_ENDPOINT_PATHS.get(realm_mod.norm_realm(realm), MODEL_ENDPOINT_PATHS["cn"])
    except ImportError:
        base = BACKEND
        paths = MODEL_ENDPOINT_PATHS["cn"]

    seen: dict = {}
    source = ""
    with httpx.Client(timeout=20, **_proxy_kwargs()) as client:
        for path in paths:
            try:
                resp = client.get(base + path, headers=headers)
            except Exception:  # noqa: BLE001  单路失败不该打断整体
                continue
            code, data = _envelope_of(resp)
            if code not in (0, 200):
                continue
            items = _model_items(data)
            if not items:
                continue
            source = source or (base + path)
            for item in items:
                mid = item.get("id") or item.get("modelName") or item.get("name")
                if not mid or str(mid) in seen:
                    continue
                seen[str(mid)] = item
    return list(seen.values()), source


def _normalize_remote_entry(entry: dict) -> dict:
    """把上游端点的条目统一成产品配置那套 camelCase 名字。

    为什么要统一：`_catalog_entry` 只认一套字段名。两个来源各写一套映射迟早漂，
    所以在这里收敛，下游只面对一种形状。
    """
    ctx = entry.get("contextWindow")
    if not isinstance(ctx, dict):
        win = entry.get("context_length") or entry.get("contextWindowLength")
        ctx = {"defaultLength": win} if win else {}
    reasoning = entry.get("reasoning")
    if not isinstance(reasoning, dict) and entry.get("reasoning_supported_efforts"):
        reasoning = {
            "effort": entry.get("reasoning_default_effort"),
            "supportedEfforts": entry.get("reasoning_supported_efforts"),
        }
    return {
        "id": entry.get("id") or entry.get("modelName") or entry.get("name"),
        "name": entry.get("name") or entry.get("displayName") or entry.get("id"),
        "vendor": entry.get("vendor") or entry.get("provider") or "",
        "descriptionZh": entry.get("descriptionZh") or entry.get("description"),
        "descriptionEn": entry.get("descriptionEn"),
        "contextWindow": ctx,
        "maxInputTokens": entry.get("maxInputTokens") or entry.get("max_input_tokens"),
        "maxOutputTokens": entry.get("maxOutputTokens") or entry.get("max_output_tokens"),
        "maxAllowedSize": entry.get("maxAllowedSize"),
        "credits": entry.get("credits") or entry.get("credit") or "",
        "supportsToolCall": bool(entry.get("supportsToolCall", entry.get("supports_tool_call"))),
        "supportsImages": bool(entry.get("supportsImages", entry.get("supports_images"))),
        "supportsReasoning": bool(entry.get("supportsReasoning", entry.get("supports_reasoning"))),
        "onlyReasoning": bool(entry.get("onlyReasoning")),
        "reasoning": reasoning,
        "temperature": entry.get("temperature"),
        "tags": [str(t) for t in (entry.get("tags") or []) if t],
    }


def get_model_catalog_for(realm: str = "cn", *, refresh: bool = False) -> list[dict]:
    """该版本的完整模型清单（带 free 标注与来源）。

    合并顺序决定「以谁为准」：`/v3/config` 等远端来源在前，本机产品配置在后
    补缺。远端拿不到时才整份退回产品配置 —— 宁可给出旧清单，也不给空清单。
    """
    import time as _time
    try:
        from admin import realm as realm_mod
        key = realm_mod.norm_realm(realm)
    except ImportError:
        key = "cn"

    now = _time.time()
    cached = _MODEL_CATALOG_CACHE.get(key)
    if cached and not refresh and now - cached["at"] < MODEL_CATALOG_TTL:
        return cached["entries"]

    remote, source = ([], "")
    try:
        remote, source = _remote_model_entries(key)
    except Exception:  # noqa: BLE001  没有单个账号可用时也不该炸
        remote, source = ([], "")

    merged: dict = {}
    order: list = []
    for item in remote:
        norm = _normalize_remote_entry(item)
        mid = norm.get("id")
        if not mid or mid in merged or not _is_chat_model_entry(norm):
            continue
        merged[mid] = norm
        order.append(mid)

    # 本机产品配置补缺（同 id 不覆盖：远端是本版本上游给的，比本机那份权威）
    local = _load_model_entries_from_workbuddy()
    local_source = ""
    if local:
        try:
            path = _find_workbuddy_product_json()
            local_source = str(path) if path else ""
        except Exception:  # noqa: BLE001
            local_source = ""
    for item in local:
        mid = item.get("id")
        if not mid or mid in merged:
            continue
        merged[mid] = item
        order.append(mid)

    if not order:
        entries = [{
            "id": mid, "name": mid, "vendor": "", "description": "",
            "context_window": None, "context_window_options": [],
            "max_input_tokens": None, "max_output_tokens": None, "max_allowed_size": None,
            "credits": "", "credit_rate": None,
            "supports_tool_call": True, "supports_images": False,
            "supports_reasoning": False, "only_reasoning": False,
            "reasoning_effort": None, "temperature": None, "tags": ["fallback"],
            "free": False,
        } for mid in DEFAULT_MODELS]
        _MODEL_CATALOG_CACHE[key] = {"at": now, "entries": entries, "source": "", "local": ""}
        return entries

    entries = []
    for mid in order:
        item = _catalog_entry(merged[mid])
        item["free"] = is_free_model(item)
        entries.append(item)

    _MODEL_CATALOG_CACHE[key] = {
        "at": now, "entries": entries,
        "source": source, "local": local_source,
    }
    return entries


def model_catalog_source(realm: str = "cn") -> dict:
    """模型清单的来源信息（给「为什么看不到某个模型」这类排查用）。

    三个字段各自的用途：
      · `remote`   —— 上游端点命中地址；空表示远端没取到，正在用本机配置
      · `local`    —— 本机产品配置文件路径
      · `realm`    —— 这份清单属于哪一版
    """
    try:
        from admin import realm as realm_mod
        key = realm_mod.norm_realm(realm)
    except ImportError:
        key = "cn"
    cached = _MODEL_CATALOG_CACHE.get(key) or {}
    return {
        "realm": key,
        "remote": cached.get("source", ""),
        "local": cached.get("local", ""),
        "count": len(cached.get("entries") or []),
    }


def _catalog_realm_or_cn(cred) -> str:
    """拿得到凭据就按它的版本，拿不到就当国内版。

    不抛：这个清单有个内置兜底（DEFAULT_MODELS），没有凭据也能给。
    在这里 503 会让「模型目录」这个排查页在**最需要它的时候**完全不可用。
    """
    return _realm_of_credential(cred) if cred is not None else "cn"


def get_model_catalog() -> list[dict]:
    """模型中心的完整清单（**当前请求所用账号所属版本**）。

    0.1.4 起不再是「读本机产品配置」一个来源：改成按版本向上游取
    （见 `get_model_catalog_for`）。产品配置退到兜底位。

    为什么不在这里换签名：`/v1/models`、密钥检查、模型中心三处都在调它，
    而它们本来就跑在「已选定账号」的上下文里 —— 版本由凭据自己决定，
    调用方不该关心。

    没有凭据时**不抛**，退回内置清单（见 `_catalog_realm_or_cn`）。
    """
    try:
        cred = _cred()
    except HTTPException:
        cred = None
    entries = get_model_catalog_for(_catalog_realm_or_cn(cred))
    return [{k: v for k, v in entry.items() if k != "free"} for entry in entries]


def get_model_catalog_with_free() -> list[dict]:
    """带 `free` 标注的模型清单（当前账号所属版本）。

    `free` 是**判据**而不是上游字段的直译，所以不放进 `_catalog_entry`；
    改判据只动 `is_free_model` 这一处。没有凭据时同样退回内置清单。
    """
    try:
        cred = _cred()
    except HTTPException:
        cred = None
    return get_model_catalog_for(_catalog_realm_or_cn(cred))


def get_available_models() -> list[str]:
    """
    获取可用的模型列表。

    优先从本机 WorkBuddy 的产品配置读取（动态缓存 > 装机快照），失败则使用 DEFAULT_MODELS。

    Returns:
        模型 ID 列表
    """
    workbuddy_models = _load_models_from_workbuddy()

    if workbuddy_models:
        # 成功从 WorkBuddy 加载，使用动态列表
        return workbuddy_models
    else:
        # 降级到硬编码列表
        return DEFAULT_MODELS


# 后端请求体里出现过的额外字段（透传时若客户端给了就保留）
PASSTHROUGH_BODY_KEYS = {
    "model",
    "messages",
    "tools",
    "tool_choice",
    "temperature",
    "max_tokens",
    "max_completion_tokens",
    "top_p",
    "stream",
    "stream_options",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "n",
    "response_format",
    "seed",
    "user",
    "reasoning_effort",
    "verbosity",
    "reasoning_summary",
}

# ---------------------------------------------------------------------------
# FastAPI 应用
# ---------------------------------------------------------------------------

app = FastAPI(title="codebuddy2openai", version="2.0")
CONFIG: dict = {
    "api_key": "",
    "cred": None,
    "log_path": None,
    "desensitize": False,
    "no_compact": False,
}  # cred: CredentialManager | None


# ---------------------------------------------------------------------------
# 日志（写文件）
# ---------------------------------------------------------------------------

_LOG_LOCK = threading.Lock()


def _log(msg: str):
    """写一行日志到 CONFIG['log_path'] 指定的文件（追加，带时间戳）。未设置则丢弃。"""
    path = CONFIG.get("log_path")
    if not path:
        return
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with _LOG_LOCK, open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass  # 日志失败不应影响主流程


# 上游拒绝（11128 渠道校验 / 内容审核等）时把完整请求与响应落盘。
#
# 与 state 里的 request-log.jsonl 互补：那边只记统计（status/tokens/outcome），
# 且失败时的 status 并不总是准（实测 11128 的 400 被记成了 200 success），
# 事后完全看不出发生了什么。这里保留上游原文和发出去的 body，
# 是定位这类问题的唯一直接证据。
_UPSTREAM_DUMP_PATH = Path.home() / ".wb-switch-plus" / "reverse-proxy" / "upstream-errors.log"
_UPSTREAM_DUMP_MAX_BYTES = 8 * 1024 * 1024


def _dump_upstream_error(url: str, headers: dict, body: dict, status: int,
                         raw: bytes, note: str = "") -> None:
    """记录一次上游拒绝的完整上下文；任何失败都静默，不影响请求本身。"""
    try:
        path = _UPSTREAM_DUMP_PATH
        try:
            if path.stat().st_size > _UPSTREAM_DUMP_MAX_BYTES:
                return
        except OSError:
            pass
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_headers = {
            k: ("***" if str(k).lower() == "authorization" else v)
            for k, v in (headers or {}).items()
        }
        messages = body.get("messages") or []
        tools = body.get("tools") or []
        serialized = json.dumps(body, ensure_ascii=False)
        entry = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": note,
            "url": url,
            "status": status,
            "summary": {
                "model": body.get("model"),
                "message_count": len(messages),
                "roles": [m.get("role") for m in messages if isinstance(m, dict)],
                "tool_count": len(tools),
                "tool_names": [
                    (t.get("function") or {}).get("name")
                    for t in tools if isinstance(t, dict)
                ],
                "body_chars": len(serialized),
                "body_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                "keys": sorted(body.keys()),
            },
            "headers": safe_headers,
            "upstream_raw": (raw or b"").decode("utf-8", "replace")[:20000],
            "request_body": serialized[:1_000_000],
        }
        with _LOG_LOCK, open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - 诊断落盘绝不影响主流程
        pass


# DSH / Codex 等 harness 的 system prompt 是固定写法，上游风控按这些
# 「指纹片段」判定请求是否来自官方客户端。实测同一段文本只换一处措辞就能
# 从 11128 变回 200（原样 400 → 改后 200，可稳定复现），所以这里做最小
# 必要打散：只换表述、保留语义，不影响 agent 对 @ 路径语法的理解。
_HARNESS_FINGERPRINT_RULES = (
    (re.compile(r"Tokens prefixed with @"), "Entries prefixed with @"),
    (re.compile(r"workspace root"), "project root"),
    (re.compile(r"DeepSeek Harness"), "Agent Harness"),
)


def _scramble_harness_fingerprint(body: dict) -> dict:
    """打散 harness prompt 里可被上游识别的特征片段，避开 11128 渠道校验。"""
    def fix(text: str) -> str:
        for pattern, replacement in _HARNESS_FINGERPRINT_RULES:
            text = pattern.sub(replacement, text)
        return text

    messages = []
    changed = False
    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            messages.append(message)
            continue
        content = message.get("content")
        if isinstance(content, str):
            new_text = fix(content)
            if new_text != content:
                changed = True
                messages.append(dict(message, content=new_text))
            else:
                messages.append(message)
        elif isinstance(content, list):
            blocks = []
            block_changed = False
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    new_text = fix(block["text"])
                    if new_text != block["text"]:
                        block_changed = True
                        changed = True
                        block = dict(block, text=new_text)
                blocks.append(block)
            messages.append(dict(message, content=blocks) if block_changed else message)
        else:
            messages.append(message)
    out = dict(body)
    if changed:
        out["messages"] = messages
    return out


def _truncate(s: str, n: int = 80) -> str:
    s = str(s).replace("\n", " ").strip()
    return s[:n] + ("…" if len(s) > n else "")


def _check_auth(authorization: str | None, x_api_key: str | None):
    key = CONFIG["api_key"]
    if not key:
        return
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token and x_api_key:
        token = x_api_key
    if token != key:
        raise HTTPException(
            status_code=401,
            detail={"error": {"message": "invalid api key", "type": "auth_error"}},
        )


def _proxy_kwargs() -> dict:
    """本轮请求应使用的出口代理（`proxy=`），没有则返回空 dict。

    出口线路是按**账号**配的（见 admin/egress.py），而选账号发生在网关中间件
    里、转发发生在下面这些 httpx 调用里，两者不在同一个函数里。所以用
    ContextVar 传递——中间件 set，这里 get，天然按请求隔离，不会有并发串号。

    独立运行（不经管理端中间件）时 ContextVar 无值，等价于直连，
    且**不会**显式传 proxy=None，因此 HTTP_PROXY 这类环境变量代理照常生效。
    """
    try:
        from admin.egress import httpx_proxy_kwargs
        return httpx_proxy_kwargs()
    except ImportError:
        return {}


def _cred() -> CredentialManager:
    # The management deployment binds one credential to each ASGI request.
    # Standalone converter usage keeps the original single-account behavior.
    try:
        from admin.pool import REQUEST_CREDENTIAL
        selected = REQUEST_CREDENTIAL.get()
        if selected is not None:
            return selected
    except ImportError:
        pass
    if CONFIG["cred"] is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "message": "未找到登录凭据，请先在桌面端登录 CodeBuddy/WorkBuddy",
                    "type": "auth_error",
                }
            },
        )
    return CONFIG["cred"]


@app.get("/health")
def health():
    cred = CONFIG["cred"]
    info: dict = {
        "status": "ok",
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "auth_file": str(find_auth_file() or "(未找到)"),
        "mode": "direct-proxy (native function calling)",
    }
    if cred is not None:
        try:
            info["credential"] = cred.summary()
        except Exception as e:
            info["credential_error"] = str(e)
    return info


@app.get("/v1/models")
def list_models(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    _check_auth(authorization, x_api_key)
    models = get_available_models()
    data = [
        {"id": m, "object": "model", "created": 1700000000, "owned_by": "codebuddy"}
        for m in models
    ]
    return {"object": "list", "data": data}


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {"message": f"bad json: {e}", "type": "invalid_request_error"}
            },
        )

    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": "messages is required",
                    "type": "invalid_request_error",
                }
            },
        )

    # 构造后端 body：只透传已知的合法字段
    client_wants_stream = bool(payload.get("stream"))
    body = {k: payload[k] for k in PASSTHROUGH_BODY_KEYS if k in payload}
    body.setdefault("model", resolve_default_model())
    # 后端只支持流式：始终以 stream=True 调后端，非流式由转换器聚合
    body["stream"] = True
    if "stream_options" not in body:
        body["stream_options"] = {"include_usage": True}

    # 腾讯后端不支持 developer role，遇到会触发安全策略拦截（11128），统一映射为 system
    if "messages" in body and isinstance(body["messages"], list):
        body["messages"] = [
            dict(m, role="system")
            if isinstance(m, dict) and m.get("role") == "developer"
            else m
            for m in body["messages"]
        ]

    body = filter_system_identity(body)
    body = _scramble_harness_fingerprint(body)

    # 可选：脱敏。缓解客户端合规模板（如 Codex CLI / ZCode 注入的说明文字）被后端误判为敏感词。
    # 处理 system / developer 消息、Codex 注入的上下文 user 消息，以及 tools 的 description。
    if CONFIG.get("desensitize"):
        body = desensitize_body(
            body,
            roles=("system", "developer"),
            desensitize_harness_user=False,
            desensitize_tools=True,
            compact_harness=not CONFIG.get("no_compact"),
            strip_tool_metadata=True,
        )

    # 日志：请求摘要
    model_name = payload.get("model", resolve_default_model())
    tool_names = [
        t.get("function", {}).get("name")
        for t in (payload.get("tools") or [])
        if isinstance(t, dict)
    ]
    last_user = _last_user_text(messages)
    rid = os.urandom(4).hex()
    _log(
        f"[{rid}] ▶ REQUEST {model_name} | stream={client_wants_stream} | msgs={len(messages)}"
        + (f" | tools={tool_names}" if tool_names else "")
        + (f" | last_user={_truncate(last_user, 60)!r}" if last_user else "")
    )
    # 完整请求体（发往后端的实际内容；若启用脱敏，这里已是脱敏后）
    _log(
        f"[{rid}] ── REQUEST BODY (发往后端) ──\n{json.dumps(body, ensure_ascii=False, indent=2)}"
    )

    headers = cred.get_headers()
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_upstream(url, headers, body, model_name, t0, rid),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：后端只支持流式，这里把后端 SSE 聚合成单个 chat.completion 响应
    try:
        async with httpx.AsyncClient(timeout=300, **_proxy_kwargs()) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    raw = await r.aread()
                    _log(
                        f"[{rid}] ✗ HTTP {r.status_code} | {model_name} | {_truncate(raw.decode('utf-8', 'replace'), 200)}"
                    )
                    _log(f"[{rid}] ── ERROR BODY ──\n{raw.decode('utf-8', 'replace')}")
                    raise HTTPException(
                        status_code=r.status_code,
                        detail=_safe_err_raw(raw, r.status_code),
                    )
                collected = await _collect_stream(r)
    except HTTPException:
        raise
    except httpx.HTTPError as e:
        _log(f"[{rid}] ✗ 网络错误 | {model_name} | {e}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": {"message": f"upstream error: {e}", "type": "upstream_error"}
            },
        )
    _log_finish(model_name, t0, collected, rid)
    return JSONResponse(content=collected)


def _last_user_text(messages: list) -> str:
    """取最后一条 user 消息的文本，用于日志预览。"""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        content = m.get("content", "")
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    return str(blk.get("text", ""))
            return ""
        return str(content)
    return ""


def _log_finish(model_name: str, t0: float, result: dict, rid: str = ""):
    """记录一次完成的请求：耗时 / finish_reason / usage / 工具调用 / 审核拦截 + 完整响应。"""
    elapsed = time.time() - t0
    prefix = f"[{rid}] " if rid else ""
    choice = (result.get("choices") or [{}])[0]
    finish = choice.get("finish_reason")
    msg = choice.get("message") or {}
    tcs = msg.get("tool_calls") or []
    usage = result.get("usage") or {}
    tag = ""
    if finish == "content-filter":
        tag = " ⚠️内容审核拦截"
    tc_names = [t.get("function", {}).get("name") for t in tcs]
    _log(
        f"{prefix}◀ RESPONSE {model_name} | {elapsed:.1f}s | finish={finish}{tag}"
        + (f" | tool_calls={tc_names}" if tc_names else "")
        + f" | tokens={usage.get('total_tokens', '?')}"
    )
    # 完整响应体
    _log(
        f"{prefix}── RESPONSE BODY ──\n{json.dumps(result, ensure_ascii=False, indent=2)}"
    )


async def _collect_stream(response: httpx.Response) -> dict:
    """消费后端的 OpenAI SSE 流，聚合成单个非流式 chat.completion 对象。

    合并所有 chunk 的 delta（content / tool_calls），并取 usage / finish_reason。
    """
    content_parts: list[str] = []
    # tool_calls: index -> {id, name, arguments(分片拼接)}
    tool_calls: dict[int, dict] = {}
    model: str | None = None
    finish_reason: str | None = None
    usage: dict | None = None

    async for line in response.aiter_lines():
        line = line.strip()
        if not line or not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue
        model = chunk.get("model") or model
        if chunk.get("usage"):
            usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]
            delta = choice.get("delta") or {}
            if delta.get("content"):
                content_parts.append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = tool_calls.setdefault(
                    idx, {"id": None, "name": None, "arguments": ""}
                )
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["arguments"] += fn["arguments"]

    tcs = None
    if tool_calls:
        tcs = [
            {
                "id": v["id"],
                "type": "function",
                "function": {"name": v["name"], "arguments": v["arguments"]},
            }
            for _, v in sorted(tool_calls.items())
        ]
        finish_reason = finish_reason or "tool_calls"

    message = {"role": "assistant", "content": "".join(content_parts) or None}
    if tcs:
        message["tool_calls"] = tcs
    return {
        "id": "chatcmpl-" + os.urandom(12).hex(),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "unknown",
        "choices": [
            {"index": 0, "message": message, "finish_reason": finish_reason or "stop"}
        ],
        "usage": usage
        or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _safe_err_raw(raw: bytes, status: int) -> dict:
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {
            "error": {
                "message": raw.decode("utf-8", "replace")[:500],
                "type": "upstream_error",
                "code": status,
            }
        }


async def _stream_upstream(
    url: str,
    headers: dict,
    body: dict,
    model_name: str = "?",
    t0: float = 0.0,
    rid: str = "",
):
    """把后端 SSE 原样转发给客户端（后端已是标准 OpenAI SSE，含 tool_calls）。

    同时轻量解析流，统计 finish_reason / tool_calls / usage 用于日志，不阻塞转发。
    完整原始 SSE 累积后落盘到日志（调试用）。
    """
    finish_reason = None
    tool_names: list[str] = []
    usage: dict = {}
    saw_filter = False
    buf = b""
    raw_parts: list[bytes] = []  # 累积完整原始 SSE
    prefix = f"[{rid}] " if rid else ""

    def _feed(chunk: bytes):
        nonlocal finish_reason, saw_filter, buf
        # 行缓冲解析：把累计的 chunk 按 data: 行切出来统计
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                continue
            try:
                obj = json.loads(data)
            except Exception:
                continue
            if obj.get("usage"):
                usage.update(obj["usage"])
            for ch in obj.get("choices") or []:
                if ch.get("finish_reason"):
                    finish_reason = ch["finish_reason"]
                for tc in (ch.get("delta") or {}).get("tool_calls") or []:
                    nm = (tc.get("function") or {}).get("name")
                    if nm:
                        tool_names.append(nm)
            # 内容审核/渠道拦截常以 content-filter、11128 或特殊中文文案返回
            try:
                text_repr = data.decode("utf-8", "replace")
            except Exception:
                text_repr = ""
            if (
                "content-filter" in text_repr
                or "敏感" in text_repr
                or "审核" in text_repr
                or "11128" in text_repr
                or "请求被拦截" in text_repr
            ):
                saw_filter = True

    try:
        async with httpx.AsyncClient(timeout=None, **_proxy_kwargs()) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    err = await r.aread()
                    _log(
                        f"{prefix}✗ HTTP {r.status_code} | {model_name} | {_truncate(err.decode('utf-8', 'replace'), 200)}"
                    )
                    _log(f"{prefix}── ERROR BODY ──\n{err.decode('utf-8', 'replace')}")
                    _dump_upstream_error(url, headers, body, r.status_code, err,
                                         note="stream-non-200")
                    yield _err_event(err, r.status_code)
                    return
                async for chunk in r.aiter_bytes():
                    if chunk:
                        raw_parts.append(chunk)
                        _feed(chunk)
                        yield chunk
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        yield _err_event(str(e).encode(), 502)

    # 流结束：输出完成日志
    elapsed = time.time() - t0 if t0 else 0
    tag = " ⚠️内容审核拦截" if (saw_filter or finish_reason == "content-filter") else ""
    _log(
        f"{prefix}◀ RESPONSE {model_name} | {elapsed:.1f}s | stream finish={finish_reason}{tag}"
        + (f" | tool_calls={tool_names}" if tool_names else "")
        + f" | tokens={usage.get('total_tokens', '?')}"
    )
    # 完整原始 SSE（后端返回的全部内容）
    _log(
        f"{prefix}── RESPONSE RAW SSE ──\n{b''.join(raw_parts).decode('utf-8', 'replace')}"
    )
    # 上游回 200 但在流里塞了拦截错误（渠道校验常见形态）——落盘留证据
    if saw_filter or finish_reason == "content-filter":
        _dump_upstream_error(url, headers, body, 200, b"".join(raw_parts),
                             note="stream-200-blocked")


def _safe_err(r: httpx.Response) -> dict:
    try:
        return {"error": r.json()}
    except Exception:
        return {
            "error": {
                "message": r.text[:500],
                "type": "upstream_error",
                "code": r.status_code,
            }
        }


def _err_event(msg: bytes, status: int) -> bytes:
    # 以 OpenAI SSE 错误 chunk 形式返回
    import json as _json

    chunk = {
        "error": {
            "message": msg.decode("utf-8", "replace")[:500],
            "type": "upstream_error",
            "code": status,
        },
    }
    return f"data: {_json.dumps(chunk, ensure_ascii=False)}\n\n".encode()


def _looks_like_content_filter_text(text: str) -> bool:
    text = (text or "").lower()
    return (
        "content-filter" in text
        or "content_filter" in text
        or "敏感内容" in text
        or "内容审核" in text
        or "无法响应您的请求" in text
        or "11128" in text
        or "illegal api invocation" in text
        or "unapproved channel" in text
        or "请求被拦截" in text
    )


def _chat_body_desensitize(body: dict, *, force_compact: bool = False) -> dict:
    if not CONFIG.get("desensitize"):
        return body
    return desensitize_body(
        body,
        roles=("system", "developer"),
        desensitize_harness_user=False,
        desensitize_tools=True,
        compact_harness=(force_compact or not CONFIG.get("no_compact")),
        strip_tool_metadata=True,
    )


async def _post_backend_once(url: str, headers: dict, body: dict) -> tuple[int, bytes]:
    async with httpx.AsyncClient(timeout=120, **_proxy_kwargs()) as c:
        async with c.stream("POST", url, headers=headers, json=body) as r:
            chunks: list[bytes] = []
            async for chunk in r.aiter_bytes():
                if chunk:
                    chunks.append(chunk)
            return r.status_code, b"".join(chunks)


async def _post_backend_with_filter_retry(
    url: str, headers: dict, body: dict, rid: str = "", model_name: str = "?"
) -> tuple[int, bytes, dict]:
    prefix = f"[{rid}] " if rid else ""
    status, raw = await _post_backend_once(url, headers, body)
    text = raw.decode("utf-8", "replace")
    if status != 200 or _looks_like_content_filter_text(text):
        _dump_upstream_error(url, headers, body, status, raw, note="non-stream")
    if (
        status == 200
        and _looks_like_content_filter_text(text)
        and CONFIG.get("desensitize")
        and CONFIG.get("no_compact")
        and os.environ.get("CODEBUDDY_RESPONSES_DESENSITIZE", "0") == "1"
    ):
        retry_body = _chat_body_desensitize(body, force_compact=True)
        _log(
            f"{prefix}↻ RESPONSES {model_name} | content filter detected, retry with compact harness"
        )
        _log(
            f"{prefix}── RESPONSES RETRY CHAT BODY ──\n{json.dumps(retry_body, ensure_ascii=False, indent=2)}"
        )
        retry_status, retry_raw = await _post_backend_once(url, headers, retry_body)
        retry_text = retry_raw.decode("utf-8", "replace")
        if retry_status == 200 and not _looks_like_content_filter_text(retry_text):
            return retry_status, retry_raw, retry_body
    return status, raw, body


# ---------------------------------------------------------------------------
# Responses API 端点（Codex CLI 兼容）
# ---------------------------------------------------------------------------


@app.post("/v1/responses")
async def create_response(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """OpenAI Responses API 兼容端点。

    Codex CLI 使用 Responses API（wire_api = "responses"）而非 Chat Completions。
    本端点接收 Responses 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Responses 语义事件流返回。
    """
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {"message": f"bad json: {e}", "type": "invalid_request_error"}
            },
        )

    # 转换请求：Responses → Chat
    try:
        chat_body = responses_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": f"request conversion error: {e}",
                    "type": "invalid_request_error",
                }
            },
        )

    chat_body = filter_system_identity(chat_body)
    chat_body = _scramble_harness_fingerprint(chat_body)
    chat_body, projection_stats = project_responses_chat_body(
        chat_body, preserve=os.environ.get("CODEBUDDY_LOSSY_PROJECTION", "0") != "1"
    )
    chat_body.setdefault("model", resolve_default_model())
    chat_body["stream"] = True
    if "stream_options" not in chat_body:
        chat_body["stream_options"] = {"include_usage": True}

    if os.environ.get("CODEBUDDY_RESPONSES_DESENSITIZE", "0") == "1":
        chat_body = _chat_body_desensitize(chat_body)

    client_wants_stream = bool(payload.get("stream", False))
    model_name = payload.get("model", resolve_default_model())
    rid = os.urandom(4).hex()
    _log(
        f"[{rid}] ▶ RESPONSES {model_name} | stream={client_wants_stream} | input_items={len(payload.get('input', []))}"
    )
    _log(
        f"[{rid}] ── RESPONSES PROJECTION ── "
        f"mode={projection_stats.get('mode')} "
        f"| msgs {projection_stats.get('original_messages')}→{projection_stats.get('projected_messages')} "
        f"| chars {projection_stats.get('original_message_chars')}→{projection_stats.get('projected_message_chars')} "
        f"| tools {projection_stats.get('original_tools')}→{projection_stats.get('projected_tools')} "
        f"| tool_chars {projection_stats.get('original_tool_chars')}→{projection_stats.get('projected_tool_chars')} "
        f"| summarized_history={projection_stats.get('summarized_history_messages', 0)} "
        f"| dropped_harness={projection_stats.get('dropped_harness_messages', 0)} "
        f"| anchor_user={projection_stats.get('anchor_user_preserved', False)}"
    )
    _log(
        f"[{rid}] ── RESPONSES → CHAT BODY ──\n{json.dumps(chat_body, ensure_ascii=False, indent=2)}"
    )

    headers = cred.get_headers()
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_responses(url, headers, chat_body, model_name, t0, rid),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：聚合后端 SSE → 非流式 Response 对象
    try:
        status_code, raw, final_body = await _post_backend_with_filter_retry(
            url, headers, chat_body, rid, model_name
        )
        if status_code != 200:
            _log(
                f"[{rid}] ✗ HTTP {status_code} | {model_name} | {_truncate(raw.decode('utf-8', 'replace'), 200)}"
            )
            raise HTTPException(
                status_code=status_code, detail=_safe_err_raw(raw, status_code)
            )
        converter = ResponsesStreamConverter(model=model_name)
        for line in raw.decode("utf-8", "replace").splitlines():
            converter.feed_line(line)
        chat_body = final_body
    except HTTPException:
        raise
    except httpx.HTTPError as e:
        _log(f"[{rid}] ✗ 网络错误 | {model_name} | {e}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": {"message": f"upstream error: {e}", "type": "upstream_error"}
            },
        )

    result = converter.get_nonstream_response()
    response_status = 200
    if result.get("error"):
        code = result["error"].get("code", "")
        response_status = int(code) if str(code).isdigit() and 400 <= int(code) <= 599 else 502
    elapsed = time.time() - t0
    _log(f"[{rid}] ◀ RESPONSES {model_name} | {elapsed:.1f}s")
    _log(
        f"[{rid}] ── RESPONSE OBJ ──\n{json.dumps(result, ensure_ascii=False, indent=2)}"
    )
    return JSONResponse(content=result, status_code=response_status)


async def _stream_responses(
    url: str,
    headers: dict,
    body: dict,
    model_name: str = "?",
    t0: float = 0.0,
    rid: str = "",
):
    """消费后端 Chat SSE，实时转换为 Responses API 事件流输出。"""
    converter = ResponsesStreamConverter(model=model_name)
    prefix = f"[{rid}] " if rid else ""

    raw_sse_lines = []
    try:
        async with httpx.AsyncClient(timeout=300, **_proxy_kwargs()) as client:
            async with client.stream("POST", url, headers=headers, json=body) as response:
                if response.status_code != 200:
                    raw = await response.aread()
                    _log(f"{prefix}✗ HTTP {response.status_code} | {model_name}")
                    yield converter.error(raw.decode("utf-8", "replace")[:500], response.status_code).encode("utf-8")
                    return
                async for line in response.aiter_lines():
                    if line.strip():
                        raw_sse_lines.append(line)
                        raw_sse_lines = raw_sse_lines[-30:]
                    events = converter.feed_line(line)
                    if events:
                        yield events.encode("utf-8")
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        yield converter.error(str(e)[:500], 502).encode("utf-8")
        return

    # 发送收尾事件
    finish_events = converter.finish()
    if finish_events:
        yield finish_events.encode("utf-8")

    elapsed = time.time() - t0 if t0 else 0
    _log(f"{prefix}◀ RESPONSES {model_name} | {elapsed:.1f}s | stream done")
    _log(f"{prefix}── RESPONSES RAW SSE ──\n" + "\n".join(raw_sse_lines[-30:]))


# ---------------------------------------------------------------------------
# Anthropic Messages API 端点（Claude Code / CC Switch 兼容）
# ---------------------------------------------------------------------------


@app.post("/v1/messages")
async def create_message(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Anthropic Messages API 兼容端点。

    Claude Code / CC Switch 使用 Anthropic Messages API（POST /v1/messages）。
    本端点接收 Anthropic 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Anthropic SSE 事件流返回。
    """
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {"message": f"bad json: {e}", "type": "invalid_request_error"}
            },
        )

    # 将 Anthropic 格式消息、工具规范在进入后端前统一转换为 OpenAI Chat 格式。
    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": "messages is required",
                    "type": "invalid_request_error",
                }
            },
        )

    try:
        chat_body = anthropic_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": f"request conversion error: {e}",
                    "type": "invalid_request_error",
                }
            },
        )

    chat_body.setdefault("model", resolve_default_model())
    # 读取用户的 stream 参数，如果未提供则默认为 True
    user_stream = payload.get("stream", True)
    # 无论用户如何设置，都向后端请求流式响应（后端只支持流式）
    chat_body["stream"] = True
    if "stream_options" not in chat_body:
        chat_body["stream_options"] = {"include_usage": True}

    chat_body = filter_system_identity(chat_body)
    chat_body = _scramble_harness_fingerprint(chat_body)
    if CONFIG.get("desensitize"):
        chat_body = desensitize_body(
            chat_body,
            roles=("system", "developer"),
            desensitize_harness_user=False,
            desensitize_tools=True,
            compact_harness=not CONFIG.get("no_compact"),
            strip_tool_metadata=True,
        )

    model_name = payload.get("model", resolve_default_model())
    chat_messages = chat_body.get("messages", [])
    rid = os.urandom(4).hex()
    _log(
        f"[{rid}] ▶ ANTHROPIC {model_name} | msgs={len(chat_messages)} | anthropic_msgs={len(messages)} | user_stream={user_stream}"
    )
    _log(
        f"[{rid}] ── ANTHROPIC → CHAT BODY ──\n{json.dumps(chat_body, ensure_ascii=False, indent=2)}"
    )

    headers = cred.get_headers()
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    # 如果用户请求流式响应，直接返回流式
    if user_stream:
        return StreamingResponse(
            _stream_anthropic(url, headers, chat_body, model_name, t0, rid),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 否则，收集完整响应并返回 JSON
    from fastapi.responses import JSONResponse

    response_data = await _collect_anthropic_nonstream(
        url, headers, chat_body, model_name, t0, rid
    )
    return JSONResponse(content=response_data)


async def _collect_anthropic_nonstream(
    url: str,
    headers: dict,
    body: dict,
    model_name: str = "?",
    t0: float = 0.0,
    rid: str = "",
) -> dict:
    """收集完整的流式响应并返回非流式 Anthropic Message 对象。"""
    converter = AnthropicStreamConverter(model=model_name)
    prefix = f"[{rid}] " if rid else ""

    try:
        async with httpx.AsyncClient(timeout=120.0, **_proxy_kwargs()) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    err = await r.aread()
                    _log(
                        f"{prefix}✗ HTTP {r.status_code} | {model_name} | {_truncate(err.decode('utf-8', 'replace'), 200)}"
                    )
                    raise HTTPException(
                        status_code=r.status_code,
                        detail={
                            "error": {
                                "message": err.decode("utf-8", "replace")[:500],
                                "type": "api_error",
                                "code": r.status_code,
                            }
                        },
                    )
                async for line in r.aiter_lines():
                    converter.feed_line(line)
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": {"message": str(e)[:500], "type": "api_error", "code": 502}
            },
        ) from None

    elapsed = time.time() - t0 if t0 else 0
    _log(f"{prefix}◀ ANTHROPIC {model_name} | {elapsed:.1f}s | nonstream done")
    return converter.get_nonstream_response()


async def _stream_anthropic(
    url: str,
    headers: dict,
    body: dict,
    model_name: str = "?",
    t0: float = 0.0,
    rid: str = "",
):
    """消费后端 OpenAI Chat SSE，实时转换为 Anthropic Messages SSE 事件流。"""
    converter = AnthropicStreamConverter(model=model_name)
    prefix = f"[{rid}] " if rid else ""

    try:
        async with httpx.AsyncClient(timeout=None, **_proxy_kwargs()) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    err = await r.aread()
                    _log(
                        f"{prefix}✗ HTTP {r.status_code} | {model_name} | {_truncate(err.decode('utf-8', 'replace'), 200)}"
                    )
                    error_evt = {
                        "type": "error",
                        "error": {
                            "message": err.decode("utf-8", "replace")[:500],
                            "type": "api_error",
                            "code": r.status_code,
                        },
                    }
                    yield f"event: error\ndata: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode()
                    return
                async for line in r.aiter_lines():
                    events = converter.feed_line(line)
                    if events:
                        yield events.encode("utf-8")
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        error_evt = {
            "type": "error",
            "error": {"message": str(e)[:500], "type": "api_error", "code": 502},
        }
        yield f"event: error\ndata: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode()
        return

    finish_events = converter.finish()
    if finish_events:
        yield finish_events.encode("utf-8")

    elapsed = time.time() - t0 if t0 else 0
    _log(f"{prefix}◀ ANTHROPIC {model_name} | {elapsed:.1f}s | stream done")


@app.post("/v1/messages/count_tokens")
async def count_tokens(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Anthropic token 计数端点。

    Claude Code 在发送消息前调用此端点获取 token 计数。
    后端只支持流式请求，所以我们发送流式请求并从中提取 usage。
    """
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {"message": f"bad json: {e}", "type": "invalid_request_error"}
            },
        )

    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": "messages is required",
                    "type": "invalid_request_error",
                }
            },
        )

    try:
        chat_body = anthropic_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": f"request conversion error: {e}",
                    "type": "invalid_request_error",
                }
            },
        )

    # 最小化实际生成：只需要 usage 统计
    chat_body.setdefault("model", resolve_default_model())
    chat_body["max_tokens"] = 1
    chat_body["stream"] = True  # 后端只支持流式
    chat_body["stream_options"] = {"include_usage": True}

    chat_body = filter_system_identity(chat_body)
    chat_body = _scramble_harness_fingerprint(chat_body)
    if CONFIG.get("desensitize"):
        chat_body = desensitize_body(
            chat_body,
            roles=("system", "developer"),
            desensitize_harness_user=False,
            desensitize_tools=True,
            compact_harness=not CONFIG.get("no_compact"),
            strip_tool_metadata=True,
        )

    headers = cred.get_headers()
    url = f"{BACKEND}/v2/chat/completions"

    try:
        async with httpx.AsyncClient(timeout=30.0, **_proxy_kwargs()) as client:
            async with client.stream(
                "POST", url, headers=headers, json=chat_body
            ) as resp:
                if resp.status_code != 200:
                    err = await resp.aread()
                    _log(
                        f"✗ count_tokens HTTP {resp.status_code}: {_truncate(err.decode('utf-8', 'replace'), 200)}"
                    )
                    raise HTTPException(
                        status_code=resp.status_code,
                        detail={
                            "error": {
                                "message": err.decode("utf-8", "replace")[:500],
                                "type": "api_error",
                                "code": resp.status_code,
                            }
                        },
                    )

                # 解析 SSE 流，查找 usage 信息
                # message_start 包含初始 usage（0），message_delta 包含真实 usage
                input_tokens = 0
                async for line in resp.aiter_lines():
                    if not line or line.startswith(":"):
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            # message_delta 事件直接包含 usage
                            if "usage" in chunk:
                                usage = chunk.get("usage") or {}
                                tokens = usage.get("prompt_tokens", 0) or usage.get(
                                    "input_tokens", 0
                                )
                                if tokens > 0:
                                    input_tokens = tokens
                            # message_start 事件在 message 对象中包含 usage
                            elif "message" in chunk and "usage" in chunk["message"]:
                                usage = chunk["message"].get("usage") or {}
                                tokens = usage.get("prompt_tokens", 0) or usage.get(
                                    "input_tokens", 0
                                )
                                if tokens > 0:
                                    input_tokens = tokens
                        except json.JSONDecodeError:
                            continue

                return {"input_tokens": input_tokens}

    except httpx.HTTPError as e:
        _log(f"✗ count_tokens network error: {e}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": {"message": str(e)[:500], "type": "api_error", "code": 502}
            },
        ) from None


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------


def preflight() -> bool:
    af = find_auth_file()
    sys.stderr.write("==== 预检 ====\n")
    sys.stderr.write(f"平台      : {sys.platform}\n")
    sys.stderr.write(f"Python    : {sys.version.split()[0]}\n")
    sys.stderr.write(f"后端      : {BACKEND} (直连，原生 function calling)\n")
    sys.stderr.write(f"登录文件  : {af or '(未找到)'}\n")
    if auth_dirs():
        sys.stderr.write(f"已查目录  : {', '.join(str(d) for d in auth_dirs())}\n")
    ok = True
    if af is None:
        sys.stderr.write(
            "\n[警告] 未找到登录文件。请在桌面端完成登录（CodeBuddy/WorkBuddy）。\n"
        )
        ok = False
    else:
        try:
            cm = CredentialManager(af)
            info = cm.summary()
            sys.stderr.write(
                f"账号      : {info.get('nickname')} / {info.get('enterpriseName')}\n"
            )
            sys.stderr.write(
                f"token过期 : {'是(将自动刷新)' if info['token_expired'] else '否'}\n"
            )
        except Exception as e:
            sys.stderr.write(f"[警告] 读取凭据失败：{e}\n")
            ok = False
    sys.stderr.write("================\n")
    return ok


def main():
    ap = argparse.ArgumentParser(
        description="CodeBuddy -> OpenAI 兼容转换器（直连后端）"
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument(
        "--api-key",
        default=os.environ.get("CODEBUDDY2OPENAI_KEY", ""),
        help="可选：要求客户端携带的 API key（默认不校验）",
    )
    ap.add_argument(
        "--log",
        default=None,
        metavar="PATH",
        help="开启日志并写到该文件（如 --log converter.log 或 --log /tmp/cb.log）。"
        "不传则不记日志。",
    )
    ap.add_argument(
        "--desensitize",
        action="store_true",
        help="启用脱敏：对 system 消息里的合规模板敏感词（DoS/exploit/credential 等）"
        "插入零宽空格，缓解被后端内容审核误拦。默认关闭。",
    )
    ap.add_argument(
        "--no-compact",
        action="store_true",
        help="配合 --desensitize 使用：跳过 system/harness 压缩，仅做零宽脱敏。"
        "保留原始 system prompt 完整内容（如 Claude Code 的行为指令），"
        "但审核误拦风险略高于默认压缩模式。",
    )
    ap.add_argument("--skip-check", action="store_true", help="跳过启动预检")
    args = ap.parse_args()

    CONFIG["api_key"] = args.api_key
    CONFIG["desensitize"] = args.desensitize
    CONFIG["no_compact"] = args.no_compact
    # --log 直接指定文件路径即开启；不传则不记
    CONFIG["log_path"] = (
        args.log if args.log else os.environ.get("CODEBUDDY2OPENAI_LOG")
    )
    af = find_auth_file()
    CONFIG["cred"] = CredentialManager(af) if af else None

    if not args.skip_check:
        preflight()

    sys.stderr.write(
        f"\n✅ 监听 http://{args.host}:{args.port}（直连后端，原生 function calling）\n"
    )
    sys.stderr.write("   GET  /v1/models\n")
    sys.stderr.write(
        "   POST /v1/chat/completions   (原生 tools/tool_calls，支持流式)\n"
    )
    sys.stderr.write("   POST /v1/responses          (Responses API，Codex CLI 兼容)\n")
    sys.stderr.write(
        "   POST /v1/messages           (Anthropic API，Claude Code / CC Switch 兼容)\n"
    )
    sys.stderr.write("   GET  /health\n")
    if args.api_key:
        sys.stderr.write("   鉴权已启用（API key 已设置）\n")
    if CONFIG["log_path"]:
        sys.stderr.write(f"   日志      : {CONFIG['log_path']}\n")
    if args.desensitize:
        mode = "零宽脱敏 + 保留全文" if args.no_compact else "零宽脱敏 + 压缩摘要"
        sys.stderr.write(f"   脱敏      : 已启用（{mode}）\n")
    sys.stderr.write("按 Ctrl+C 退出。\n\n")

    # 启动时写一条标记
    _log("==== converter 启动 ====")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
