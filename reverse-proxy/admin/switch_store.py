"""SwitchStore —— 把 WB-Switch-Plus 的账号库（~/.wb-switch-plus/accounts.json）接入 codebuddy2api。

与 admin.server.Store 的差别：
  · 账号来源是 WB-Switch-Plus 的账号库（JSON 数组），不是本服务目录下的 .info 文件；
  · 账号的增删由 WB-Switch-Plus 负责，本服务**只读**账号库；
  · 密钥 / 会话 / 账号池设置仍保存在本服务自己的 state.json。

契约：本类实现 Store 被 AccountPool / PoolMiddleware / create_app 用到的全部接口，
因此 codebuddy2api 的池化、协议转换、管理鉴权等逻辑**无需改动**即可复用。

账号库记录（workbuddy-switch 的字段）→ codebuddy2api 需要的 {auth, account} 形状：
  access_token / refresh_token（明文或 $wbEncrypted 信封）、expiresAt（毫秒）、
  refreshExpiresAt、domain、uid、nickname、enterpriseId、variant(cn/ai) → realm。
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from collections import deque
from pathlib import Path

import httpx
from fastapi import HTTPException

from core import converter
from core.workbuddy_atrest_crypto import decrypt_auth_field, encrypt_auth_field, is_encrypted_field

from . import accountid
from . import realm as realm_mod

DEFAULT_DOMAIN = converter.DEFAULT_DOMAIN
BACKEND = converter.BACKEND


# ── 小工具（与 admin.server 同形，本地实现以避免循环导入）──────────────
def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def write_json(path: Path, value) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)


# ── 运行时长落盘（runtime.json）────────────────────────────────────────
#
# 用户的要求是「已运行时间也写入文件里 统计总运行时间」。
#
# ⚠️ 关键设计约束：这不是第二个真相源。
#   state.json 的 `runtime_total_sec` / `runtime_since` 仍是唯一真相源
#   （由 uptime() 现算）。runtime.json 只是它的投影，给人和脚本看。
#   一旦这里自己计时，两份必然漂移 —— 那就制造了一个「该信哪个」的问题。
#
# 为什么要定期写，而不是只在退出时写：
#   本机 WMI 已损坏（taskkill 常失败），服务又是被 Tauri 拉起的，
#   强杀 / 崩溃 / 断电都很常见。只在 atexit 写的话，这些情形一份记录都留不下
#   —— 而「跑了多久」恰恰是崩溃后最想知道的信息。
RUNTIME_FILENAME = "runtime.json"
RUNTIME_WRITE_INTERVAL_SEC = 60.0


def _server_started_at_from(state_path: Path):
    """从 state.json 里取「这台机器上最早一次启动」的时刻，用于
    `first_started_at`。取不到就返回 None（首次运行）。

    从 state.json 读而不是在 runtime.json 里自己维护：
    后者会因为「runtime.json 被删而 state.json 还在」而把首次时间重置，
    而 state.json 才是权威。
    """
    try:
        doc = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    value = doc.get("runtime_first_started_at")
    return int(value) if isinstance(value, (int, float)) else None


# ── 账号库读取与字段映射 ────────────────────────────────────────────────
def switch_accounts_path() -> Path:
    """账号库路径：环境变量优先，缺省 ~/.wb-switch-plus/accounts.json。

    目录名跟桌面端（`config::store_dir()`）保持一致：这是二改版，
    刻意不用上游的 `~/.wb-switch`，免得两个程序互相覆盖账号库。
    """
    env = os.environ.get("WB_SWITCH_ACCOUNTS")
    if env:
        return Path(env)
    return Path.home() / ".wb-switch-plus" / "accounts.json"


def read_switch_accounts(path: Path) -> list[dict]:
    """读取账号库（JSON 数组）；文件缺失 / 损坏时返回空列表。"""
    return read_switch_accounts_checked(path)[0]


def read_switch_accounts_checked(path: Path) -> tuple[list[dict], bool]:
    """读取账号库，并区分「确实是空的」与「这次读不到」。

    返回值第二项为 False 表示文件暂时不可读（正在被写入、被占用等）——
    调用方必须保留原有状态，绝不能把这种瞬时失败当成「账号全被删了」。
    switch 侧用原子替换写文件，正常不会读到半截内容；这里的兜底针对
    Windows 上替换瞬间被占用、或账号库尚未创建时的竞态。
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], True  # 账号库不存在 = 没有账号（首次运行 / 还没登录过）
    except OSError:
        return [], False
    try:
        raw = json.loads(text)
    except ValueError:
        return [], False
    if isinstance(raw, dict):
        for key in ("accounts", "items"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
    if not isinstance(raw, list):
        return [], False
    records = [r for r in raw if isinstance(r, dict)]
    # 补 id：桌面端切换账号按 id（或 uid）查号，缺 id 的记录在桌面端「看得到但切不过去」。
    # 这里只补内存副本，不写回文件 —— 文件归桌面端所有，反代服务擅自整份重写会
    # 丢掉它自己的字段（createdAt / profile_raw / 会话绑定等）。
    for rec in records:
        accountid.ensure_account_id(rec)
    return records, True


def variant_of(rec: dict) -> str:
    """档位：ai / global / intl → international，其余 → cn。"""
    v = str(rec.get("variant") or rec.get("realm") or "").strip().lower()
    return "ai" if v in ("ai", "global", "intl", "international") else "cn"


def account_key(rec: dict) -> str:
    """账号稳定标识：优先 uid；缺失时退回 email / nickname。"""
    for key in ("uid", "email", "nickname"):
        value = str(rec.get(key) or "").strip()
        if value:
            return value
    return "acct-" + secrets.token_hex(4)


def account_label(rec: dict) -> str:
    for key in ("note", "nickname", "email", "uid"):
        value = str(rec.get(key) or "").strip()
        if value:
            return value[:60]
    return "未命名账号"


def record_to_doc(rec: dict) -> dict:
    """switch 账号记录 → codebuddy2api 的 {auth, account} 形状。

    access_token / refresh_token 原样透传（可能是明文，也可能是 $wbEncrypted 信封对象）——
    与 switch 的 secret_value 语义一致：只在真正发请求时解密。
    """
    profile = rec.get("profile_raw") if isinstance(rec.get("profile_raw"), dict) else {}
    domain = str(rec.get("domain") or profile.get("domain") or DEFAULT_DOMAIN)
    expires_at = rec.get("expiresAt") or 0
    return {
        "auth": {
            "accessToken": rec.get("access_token", ""),
            "refreshToken": rec.get("refresh_token", ""),
            "expiresAt": expires_at,
            "refreshExpiresAt": rec.get("refreshExpiresAt") or expires_at,
            "domain": domain,
            "tokenType": "Bearer",
        },
        "account": {
            "uid": str(rec.get("uid") or ""),
            "nickname": str(rec.get("nickname") or profile.get("nickname") or ""),
            "enterpriseId": str(rec.get("enterpriseId") or profile.get("enterpriseId") or ""),
            "email": str(rec.get("email") or profile.get("email") or ""),
        },
        "realm": variant_of(rec),
    }


class SwitchCredentialManager:
    """以 switch 账号库记录为后端的凭据管理器，接口与 core.converter.CredentialManager 一致。

    与 converter.CredentialManager 的差别：
      · 数据源是账号库里的**一条记录**，不是 .info 文件；
      · 刷新后的 token 默认只留在内存（`WB_SWITCH_WRITE_BACK=1` 时才原子回写账号库），
        避免与 workbuddy-switch 自身对同一文件的写入互相覆盖。
    """

    def __init__(self, path: Path, account_id: str):
        self.path = Path(path)
        self.account_id = account_id
        self._lock = threading.Lock()
        self._cached: dict | None = None
        self._mtime: float = 0.0

    # ── 读 ──
    def _load(self) -> dict:
        for rec in read_switch_accounts(self.path):
            if account_key(rec) == self.account_id:
                return record_to_doc(rec)
        raise RuntimeError(f"账号不存在：{self.account_id}")

    def _load_if_stale(self) -> None:
        try:
            mt = self.path.stat().st_mtime
        except OSError:
            mt = 0.0
        if self._cached is None or mt != self._mtime:
            self._cached = self._load()
            self._mtime = mt

    def _session(self) -> dict:
        self._load_if_stale()
        if self._cached is None:
            raise RuntimeError(f"无法读取账号：{self.account_id}")
        return self._cached

    def _is_expired(self) -> bool:
        s = self._session()
        expires_at = (s.get("auth") or {}).get("expiresAt") or 0
        return time.time() * 1000 >= (expires_at - 60_000)

    # ── 请求头（与 converter 逐字一致）──
    def _build_headers_from(self, auth: dict, account: dict) -> dict:
        domain = auth.get("domain") or DEFAULT_DOMAIN
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {decrypt_auth_field(auth.get('accessToken', ''))}",
            "X-User-Id": account.get("uid", ""),
            "X-Enterprise-Id": account.get("enterpriseId", ""),
            "X-Tenant-Id": account.get("enterpriseId", ""),
            "X-Domain": domain,
            "User-Agent": converter.USER_AGENT,
        }

    def get_headers(self) -> dict:
        with self._lock:
            if self._is_expired():
                self._refresh()
            s = self._session()
            return self._build_headers_from(s.get("auth") or {}, s.get("account") or {})

    # ── 刷新 ──
    def _refresh(self) -> None:
        s = self._session()
        auth = s.get("auth") or {}
        headers = self._build_headers_from(auth, s.get("account") or {})
        headers["X-Refresh-Token"] = decrypt_auth_field(auth.get("refreshToken", ""))
        headers["X-Auth-Refresh-Source"] = "plugin"
        url = f"{converter._backend_base_of(self)}/v2/plugin/auth/token/refresh"
        try:
            with httpx.Client(timeout=15) as c:
                r = c.post(url, headers=headers, json={})
            data = r.json()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"刷新 token 网络失败：{e}")
        if data.get("code") != 0 or not data.get("data"):
            raise RuntimeError(f"刷新 token 失败：{data.get('msg', data)}")
        new_auth = data["data"]
        if not isinstance(new_auth, dict) or not new_auth.get("accessToken"):
            raise RuntimeError("刷新响应缺少访问令牌")
        new_auth["refreshToken"] = new_auth.get("refreshToken") or decrypt_auth_field(
            auth.get("refreshToken", "")
        )
        new_auth["domain"] = new_auth.get("domain") or auth.get("domain")
        new_auth["lastRefreshTime"] = int(time.time() * 1000)
        if not new_auth.get("expiresAt") and new_auth.get("expiresIn"):
            new_auth["expiresAt"] = int(time.time() * 1000) + new_auth["expiresIn"] * 1000
        if not new_auth.get("refreshExpiresAt") and new_auth.get("refreshExpiresIn"):
            new_auth["refreshExpiresAt"] = int(time.time() * 1000) + new_auth["refreshExpiresIn"] * 1000
        # 原文件是加密信封时，回写前重新加密（与 converter 同口径）
        if is_encrypted_field(auth.get("accessToken")):
            new_auth["accessToken"] = encrypt_auth_field(decrypt_auth_field(new_auth["accessToken"]))
            new_auth["refreshToken"] = encrypt_auth_field(decrypt_auth_field(new_auth["refreshToken"]))
        s["auth"] = new_auth
        self._cached = s
        if os.environ.get("WB_SWITCH_WRITE_BACK") == "1":
            self._write_back(new_auth)

    def _write_back(self, new_auth: dict) -> None:
        """把刷新结果写回 switch 账号库（默认关闭；开关见 WB_SWITCH_WRITE_BACK）。"""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        target = None
        if isinstance(raw, list):
            for rec in raw:
                if isinstance(rec, dict) and account_key(rec) == self.account_id:
                    target = rec
                    break
        if target is None:
            return
        target["access_token"] = new_auth.get("accessToken", target.get("access_token"))
        target["refresh_token"] = new_auth.get("refreshToken", target.get("refresh_token"))
        if new_auth.get("expiresAt"):
            target["expiresAt"] = new_auth["expiresAt"]
        if new_auth.get("refreshExpiresAt"):
            target["refreshExpiresAt"] = new_auth["refreshExpiresAt"]
        try:
            write_json(self.path, raw)
        except OSError:
            pass

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
            # 端点分域要靠这两项：`_realm_of_credential` 只认 realm/domain，
            # 缺了它们国际版账号会被一律当成国内版（打错网关 → 401）。
            # `record_to_doc` 已经把版本算成 realm 了，这里只是把它带出来。
            "realm": s.get("realm") or auth.get("realm") or auth.get("variant"),
            "domain": auth.get("domain"),
        }


# ── Store ──────────────────────────────────────────────────────────────
class SwitchStore:
    """Store 的替代实现：账号来自 switch 账号库，其余状态存本服务 state.json。"""

    def __init__(self, root, accounts_path=None, initial_key: str = "", admin_key: str = ""):
        if len(admin_key) < 20:
            raise RuntimeError("ADMIN_KEY must contain at least 20 characters")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.accounts_path = Path(accounts_path) if accounts_path else switch_accounts_path()
        self.auth_dir = self.accounts_path.parent  # 供个别管理接口只读使用
        self.lock = threading.RLock()
        self.admin_digest = digest(admin_key)
        self.admin_key = admin_key
        self.sessions: dict = {}
        self.attempts: dict = {}
        self.test_lock = asyncio.Lock()
        self.test_keys: set = set()
        self.managers: dict = {}
        self.started = time.time()          # 本次进程启动时刻（「已运行」用它）
        # 累计运行时间：把「上次关机时已累计的秒数」从 state.json 读回来，
        # 之后由 uptime() 现算。为什么需要它：`started` 只活在这个进程里，
        # 一重启就归零 —— 用户看到「已运行 2 分钟」，但他其实已经用了两周，
        # 那个数字对「这服务稳不稳」这个问题毫无帮助。
        self.events = deque(maxlen=40)
        self.path = self.root / "state.json"
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                self.data = {"accounts": {}, "active": None, "keys": {}}
        else:
            self.data = {"accounts": {}, "active": None, "keys": {}}
        self.data.setdefault("keys", {})
        self.data.setdefault("active", None)
        # `accounts` 是运行时视图：每次都由账号库重建，`save()` 刻意不落盘
        # （见 save()）。因此从磁盘读回的 data 里没有这个键，必须在这里补回来——
        # 否则紧接着的 sync_from_switch() 一读到 `data["accounts"]` 就 KeyError，
        # 表现为「服务第二次启动直接崩溃」。
        self.data.setdefault("accounts", {})
        # 累计运行时间。`runtime_total_sec` = 之前所有会话累计的秒数，
        # `runtime_since` = 本次会话开始写入的时刻（用墙钟，便于跨重启相加）。
        # 两个键都惰性补默认值，老 state.json 不需要迁移。
        self.data.setdefault("runtime_total_sec", 0)
        self.data.setdefault("runtime_since", int(self.started))
        # 进程正常退出时把这一段累加回去。用 atexit 而不是 save()：
        # save() 每次管理操作都会调，在里面累加会把同一段时间重复计入。
        self._runtime_flushed = False
        atexit.register(self.flush_runtime)
        # `runtime_first_started_at` = 这台机器上最早一次启动的时刻。
        # 惰性补默认值：老 state.json 没有这个键，第一次补上就是「首次启动」。
        # 只在缺失时写，之后永不覆盖 —— 否则每次启动都重置，
        # 用户永远看不到「我用这服务用多久了」。
        if not isinstance(self.data.get("runtime_first_started_at"), (int, float)):
            self.data["runtime_first_started_at"] = int(self.started)
        # 会话计数：每次成功构造一个 store 就算一次启动。
        self.data["runtime_sessions"] = int(self.data.get("runtime_sessions") or 0) + 1
        self._runtime_path = self.root / RUNTIME_FILENAME
        self._runtime_stop = threading.Event()
        self._runtime_thread: threading.Thread | None = None
        self._runtime_interval: float | None = None
        # 账号库指纹（mtime_ns, size）：热加载靠它判断要不要重读
        self._accounts_sig: tuple[int, int] | None = None
        self.sync_from_switch()
        if initial_key:
            self.add_key("原有 API Key", initial_key)
        self.save()
        self.sync_active()
        # 先写一次：让 runtime.json 在启动瞬间就存在，
        # 而不是等第一个 interval 过去。否则「刚起来就被杀」这个
        # 最常见的崩溃场景仍然一份记录都留不下。
        self.write_runtime_file()
        # 定期写入。默认开着；测试里可以用 WB_RUNTIME_WRITER=0 关掉，
        # 用来验证「关掉之后验收点确实会红」——不失败 = 不存在。
        if os.environ.get("WB_RUNTIME_WRITER", "1").strip() not in ("0", "false", "no", "off"):
            self.start_runtime_writer()

    # ── 账号库同步（只读 + 本地覆盖）─────────────────────────────────
    #
    # 关于「谁说了算」：
    #   · 账号的存在性与凭据以 workbuddy-switch 账号库为唯一权威；
    #   · 「启用 / 暂停 / 改名 / 从本服务移除」是本服务的视图，存在
    #     `account_overrides` 里，这样账号库一变就被重置的问题不会发生。

    def _overrides_lock_free(self) -> dict:
        """本地覆盖表（调用方需已持有 self.lock）。"""
        return self.data.setdefault("account_overrides", {})

    def apply_override(self, aid: str, **values) -> None:
        """写入某个账号的本地覆盖（enabled / name / hidden）。"""
        with self.lock:
            entry = self._overrides_lock_free().setdefault(aid, {})
            for key, value in values.items():
                if value is None:
                    entry.pop(key, None)
                else:
                    entry[key] = value
            if not entry:
                self._overrides_lock_free().pop(aid, None)
            self.save()

    def _drop_from_view(self, aids) -> None:
        """把若干账号从当前视图里摘掉，并回收它们的运行态。

        与 `refresh_accounts()` 的区别：这里只按**已知的 id** 摘除，
        不需要读账号库，因此账号库恰好不可读时「移除」也能立刻生效。
        """
        with self.lock:
            status = self.data.get("account_status") or {}
            bindings = self.data.get("session_bindings") or {}
            for aid in aids:
                self.data["accounts"].pop(aid, None)
                status.pop(aid, None)
                self.managers.pop(aid, None)
                for key in [k for k, v in bindings.items() if v.get("account_id") == aid]:
                    bindings.pop(key, None)
            if self.data.get("active") not in self.data["accounts"]:
                self.data["active"] = next(
                    (a for a in self.data["accounts"] if self.data["accounts"][a]["enabled"]), None
                )
            self.save()
            self.sync_active()

    def hide_account(self, aid: str) -> None:
        """从本服务移除该账号（只影响本服务的调度视图，不动账号库）。"""
        self.apply_override(aid, hidden=True)
        self._drop_from_view([aid])
        # 账号库可读时顺带对齐一次（昵称变化等）；不可读也不影响上面的摘除。
        self.refresh_accounts()

    def set_enabled(self, aid: str, enabled: bool) -> None:
        self.apply_override(aid, enabled=bool(enabled))
        with self.lock:
            if aid in self.data["accounts"]:
                self.data["accounts"][aid]["enabled"] = bool(enabled)
                if not enabled and self.data.get("active") == aid:
                    self.data["active"] = None
            self.sync_active()

    def set_active(self, aid: str) -> None:
        with self.lock:
            item = self.data["accounts"].get(aid)
            if not item:
                raise KeyError(aid)
            if not item["enabled"]:
                raise ValueError("请先启用账号")
            self.data["active"] = aid
            self.save()
            self.sync_active()

    def refresh_accounts(self, force: bool = False) -> dict:
        """检测账号库变化并热重载账号视图（无需重启服务）。

        返回变更摘要：
          {"changed": bool, "stale": bool, "added": [...], "removed": [...],
           "renamed": [...], "total": int, "active": aid|None}

        `stale=True` 表示这次没读到账号库（文件被占用 / 半截内容），
        状态保持原样，等下一次轮询。
        """
        # 先比指纹：绝大多数调用只有一次 stat()，零额外开销。
        try:
            st = self.accounts_path.stat()
            sig: tuple[int, int] | None = (st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        if not force and sig == self._accounts_sig:
            with self.lock:
                return {"changed": False, "stale": False, "added": [], "removed": [],
                        "renamed": [], "total": len(self.data["accounts"]),
                        "active": self.data.get("active")}

        records, ok = read_switch_accounts_checked(self.accounts_path)
        if not ok:
            # 瞬时不可读：保留现状，绝不把账号清空。
            with self.lock:
                return {"changed": False, "stale": True, "added": [], "removed": [],
                        "renamed": [], "total": len(self.data["accounts"]),
                        "active": self.data.get("active")}

        with self.lock:
            previous = dict(self.data["accounts"])
            over = self._overrides_lock_free()
            rebuilt: dict = {}
            for rec in records:
                aid = account_key(rec)
                ov = over.get(aid) or {}
                if ov.get("hidden"):
                    continue
                prior = previous.get(aid) or {}
                label = account_label(rec)
                # 名称优先用本地改名；否则跟随账号库的昵称/备注。
                rebuilt[aid] = {
                    "file": aid,
                    "name": ov.get("name") or label,
                    "enabled": bool(ov.get("enabled", prior.get("enabled", True))),
                    "created": prior.get("created", 0),
                }

            added = sorted(a for a in rebuilt if a not in previous)
            removed = sorted(a for a in previous if a not in rebuilt)
            renamed = sorted(a for a in rebuilt if a in previous
                             and previous[a].get("name") != rebuilt[a]["name"])

            # 账号删除后，指向它的缓存/绑定/凭据管理器一并回收，避免僵尸状态。
            status = self.data.get("account_status") or {}
            self.data["account_status"] = {k: v for k, v in status.items() if k in rebuilt}
            bindings = self.data.get("session_bindings") or {}
            self.data["session_bindings"] = {
                k: v for k, v in bindings.items() if v.get("account_id") in rebuilt
            }
            if removed:
                for aid in removed:
                    self.managers.pop(aid, None)

            self.data["accounts"] = rebuilt
            active = self.data.get("active")
            if active not in rebuilt:
                # 目标账号没了（或从未选过）：让位给第一个启用中的账号。
                active = next((a for a in rebuilt if rebuilt[a]["enabled"]), None) or next(iter(rebuilt), None)
                self.data["active"] = active
            self.save()
            self.sync_active()

        self._accounts_sig = sig
        changed = bool(added or removed or renamed or force)
        if (added or removed) and previous:
            # 控制台上留一条痕迹，方便 exe 直接运行时定位「账号怎么没生效」。
            # 首次加载不打印（那时还没得比较）；控制台编码不支持中文时也不能崩。
            bits = []
            if added:
                bits.append(f"+{len(added)}")
            if removed:
                bits.append(f"-{len(removed)}")
            try:
                print(f"[accounts] 账号库已重载（{' '.join(bits)}）：现共 {len(rebuilt)} 个账号",
                      file=sys.stderr)
            except Exception:  # noqa: BLE001 - 打印失败不该影响热加载
                pass
        return {"changed": changed, "stale": False, "added": added, "removed": removed,
                "renamed": renamed, "total": len(rebuilt), "active": self.data.get("active")}

    def sync_from_switch(self) -> None:
        """兼容入口：强制按账号库刷新账号视图。"""
        self.refresh_accounts(force=True)


    def save(self) -> None:
        # 账号由 switch 负责，不写进 state.json；只落盘 keys / active / 池设置
        payload = {k: v for k, v in self.data.items() if k != "accounts"}
        try:
            write_json(self.path, payload)
        except OSError as exc:
            # 不要静默吞掉。
            #
            # 别处的 `except OSError: pass` 是合理的（例如 refresh_accounts
            # 里 stat 失败 —— 下一轮会重试）。但 save() 不一样：它兜的是
            # 管理端改动的落盘。写失败（只读挂载、磁盘满、权限）之后，
            # 接口照样返回 200，用户以为「密钥建好了」；
            # 真相要到重启后才发现 —— 那时表现成「我的密钥全没了」，
            # 而日志里一条线索都没有。
            #
            # 仍然不往上抛：调用方大多是请求路径，不该因为落盘失败就 500。
            # 但至少要在 stderr 留下痕迹，让「东西没存住」这件事可查。
            print(f"[reverse-proxy] 状态落盘失败（{self.path}）：{exc}", file=sys.stderr)

    def uptime(self) -> dict:
        """运行时长：`session` = 本次进程，`total` = 累计（含历次）。

        两个数都要给：
          * 已运行（session）回答「这次起来多久了」——重启后应该归零。
          * 累计运行（total）回答「这服务总体跑了多久」——重启不该清零，
            否则用户永远看不到自己实际用了多久。

        计算方式：total = 上次累计 + (现在 - 本次会话起点)。
        本次会话起点存在 state.json（`runtime_since`），所以**即使中途异常退出、
        没来得及走 atexit，下次启动也会把这段时间算进去**（墙钟相减，不依赖回调）。
        """
        now = time.time()
        since = int(self.data.get("runtime_since") or int(self.started))
        # 墙钟可能被改（对时 / 夏令时 / 手动调整），导致 now < since。
        # 这种时候这一段就按 0 算，绝不产生负数——界面显示负数比不显示更糟。
        this_session = max(0, int(now) - since)
        previous = max(0, int(self.data.get("runtime_total_sec") or 0))
        return {
            "session": max(0, int(now) - int(self.started)),
            "total": previous + this_session,
            "since": int(self.started),
            "total_since": since,
        }

    def flush_runtime(self) -> None:
        """把本次会话的时长累加进 `runtime_total_sec` 并落盘。进程退出时调一次。

        幂等：`_runtime_flushed` 保证重复调用（atexit + 显式调用）只累加一次，
        否则同一段时间会被算两遍，累计值越跑越虚。
        """
        if self._runtime_flushed:
            return
        self._runtime_flushed = True
        try:
            with self.lock:
                now = int(time.time())
                since = int(self.data.get("runtime_since") or int(self.started))
                self.data["runtime_total_sec"] = (
                    max(0, int(self.data.get("runtime_total_sec") or 0))
                    + max(0, now - since))
                self.data["runtime_since"] = now
                self.save()
        except Exception:  # noqa: BLE001
            # 退出路径上不能抛：atexit 里的异常只会打一行噪音，还可能
            # 干扰正常的关闭流程。累计值丢一次不影响服务本身。
            pass
        # 顺带把最新值投影到 runtime.json —— 正常退出后文件立即是新的，
        # 不必等下一次定期写入。失败不影响退出。
        self.write_runtime_file()

    # ── 运行时长投影到文件 ──────────────────────────────────────────

    def runtime_snapshot(self) -> dict:
        """要写进 runtime.json 的内容。**值全部来自 uptime()**，不另起计时。"""
        up = self.uptime()
        now = int(time.time())
        first = self.data.get("runtime_first_started_at")
        first = int(first) if isinstance(first, (int, float)) else up["total_since"]
        return {
            # 用户说的「总运行时间」= 累计（含历次会话）。
            "total_sec": int(up["total"]),
            # 「已运行时间」= 本次会话。重启归零。
            "session_sec": int(up["session"]),
            "sessions": int(self.data.get("runtime_sessions") or 1),
            "first_started_at": first,
            "session_started_at": int(up["since"]),
            "last_seen_at": now,
            "updated_at": now,
            # 说明这份文件是投影而不是真相源，避免后来的人拿它当真。
            "source": "state.json#runtime_total_sec",
        }

    def write_runtime_file(self) -> bool:
        """把当前运行时长写到 `runtime.json`（`state.json` 的同目录）。

        返回是否写成功。**任何异常都不往上抛** —— 它是旁路：
        写不出去（只读挂载 / 磁盘满 / 权限）不该让服务或退出路径失败。
        与 `save()` 的区别：`save()` 兜的是「管理端改动的落盘」，丢了要报；
        这里丢的是**展示用副本**，下次定期写入会补上，所以只吞不报。
        """
        try:
            with self.lock:
                payload = self.runtime_snapshot()
            write_json(self._runtime_path, payload)
            return True
        except Exception:  # noqa: BLE001
            # 刻意吞掉：这条路径会被定期线程和 atexit 调用，
            # 任何异常都不该影响主流程或阻止进程退出。
            return False

    def start_runtime_writer(self,
                             interval: float = RUNTIME_WRITE_INTERVAL_SEC) -> None:
        """起一个 **daemon** 线程，每 `interval` 秒把运行时长投影到文件。

        为什么用线程而不是复用某个 tick：本服务没有统一的定时器
        （请求是事件驱动的，闲时一个请求都没有）。要「闲时也在写」
        就只能自己起一个。

        为什么必须是 daemon 线程：本服务由 Tauri 拉起，
        退出路径绝不能因为它卡住。daemon 线程不阻止解释器退出；
        `stop_runtime_writer()` 还会让它尽快睡着退出，
        加上 `wait()` 带超时，最坏情况也只是多等 deadline。

        幂等：重复调用只起一个线程。
        """
        # 已经有一个线程在跑：不能直接 return。
        #
        # 我第一版就是直接 return，结果是「调用方传了新 interval 却被静默忽略」——
        # 我的验收脚本传了 interval=0.4 想快点看到效果，实际仍在睡 60 秒，
        # 表现为「线程活着、文件却一直不更新」。这种「参数被吞掉」的 API
        # 比报错更坏：调用方以为设上了。
        #
        # 所以：已有的线程停掉再按新 interval 起（带超时，不会卡）。
        # 间隔没变时也只是多一次 join，代价可忽略。
        existing = self._runtime_thread
        if existing is not None and existing.is_alive():
            if getattr(self, "_runtime_interval", None) == interval:
                return          # 真幂等：同间隔重复调用是空操作
            self.stop_runtime_writer()
        self._runtime_interval = interval
        self._runtime_stop.clear()

        def _tick() -> None:
            # wait() 返回 True 表示收到了停止信号 —— 用它当 sleep，
            # 退出时能立刻醒来，不必干等满一个 interval。
            while not self._runtime_stop.wait(interval):
                self.write_runtime_file()

        thread = threading.Thread(
            target=_tick,
            name="wb-runtime-writer",
            daemon=True,   # ← 硬要求：绝不能阻止进程退出
        )
        self._runtime_thread = thread
        thread.start()

    def stop_runtime_writer(self, timeout: float = 2.0) -> None:
        """停掉定期写入线程。幂等，且**带超时**，绝不无限等。"""
        self._runtime_stop.set()
        thread = self._runtime_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        self._runtime_thread = None

    # ── 上下文管理器：把「停线程」变成结构性保证 ──────────────────────
    #
    # 为什么需要它：`start_runtime_writer()` 起的 daemon 线程会**一直活着**，
    # 每 interval 秒调一次 `write_runtime_file()`（内部走 `os.replace`）。
    # 一个用例 `setUp` 建了 store 却从不 `stop_runtime_writer()`，
    # 线程就留到**后续用例**里继续跑。
    #
    # 后果实测过（`_hyact_work/prove_thread_leak.py`，三条证据齐全）：
    #   · 连建 10 只 store -> 10 个 `wb-runtime-writer` 线程存活；
    #   · 1 秒内 `os.replace` 被这些线程调了 4 次；
    #   · `test_repeated_appends_do_not_rewrite_the_file_every_time`
    #     用「replace 被调了几次」判断实现对不对，
    #     于是被别人的线程污染成 **单跑绿、全量红**。
    #
    # 单测里逐个补 `stop_runtime_writer()` 也能修，但那是「靠记性」——
    # 下一个人再写一个用例又会漏。所以给 store 本身加 `with` 支持：
    # 只要用 `with make_store() as store:`，线程在退出块时必然被停。
    def __enter__(self) -> "SwitchStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop_runtime_writer()
        return False            # 不吞异常：异常照常向上抛

    def account_rows(self) -> list[dict]:
        # 每次读取前先按指纹判断账号库有没有变——管理端刷新 / 池选号
        # 都会走到这里，所以「switch 里加了账号」下一次请求就能看到。
        self.refresh_accounts()
        result = []
        records = {account_key(r): r for r in read_switch_accounts(self.accounts_path)}
        for aid, item in self.data["accounts"].items():
            rec = records.get(aid)
            # 口径统一走 realm.realm_of（返回 cn / global）。原来这里用 variant_of
            # 返回的是 cn / ai，同一个账号在「账号行」叫 ai、在「签到分派」叫
            # global，前端得同时认两套拼写，迟早有一处漏。
            row_realm = realm_mod.realm_of({
                "realm": (rec or {}).get("realm") or "",
                "domain": (rec or {}).get("domain") or "",
                # 存量记录可能只写了 variant="ai"，没有 realm 字段。
                "variant": (rec or {}).get("variant") or "",
            })
            row = {
                "id": aid,
                "name": item["name"],
                "enabled": item["enabled"],
                "active": aid == self.data["active"],
                "created": item["created"],
                "realm": row_realm,
                # 这两个字段由 realm 模块统一给出，界面不自己推：
                # 国际版（workbuddy.ai）没有签到体系，点签到必然拿错误码，
                # 界面若照常显示「今日未确认签到」就会永远亮着一条消不掉的提示。
                "realm_label": realm_mod.realm_label(row_realm),
                "checkin_supported": realm_mod.supports_checkin(row_realm),
            }
            if rec is None:
                row.update({"status": "missing", "expired": True, "expires_at": 0,
                            "refresh_available": False})
            else:
                expiry = rec.get("expiresAt", 0) or 0
                row.update({
                    "nickname": str(rec.get("nickname") or ""),
                    "uid": str(rec.get("uid") or ""),
                    "expires_at": expiry,
                    "expired": bool(expiry) and expiry < time.time() * 1000,
                    "refresh_available": bool(rec.get("refresh_token")),
                    "status": "ready",
                })
            result.append(row)
        return result

    def manager_for(self, aid, item):
        with self.lock:
            if aid not in self.managers:
                self.managers[aid] = SwitchCredentialManager(self.accounts_path, aid)
            return self.managers[aid]

    def file_for(self, item):
        return self.accounts_path

    def sync_active(self) -> None:
        aid = self.data.get("active")
        item = self.data["accounts"].get(aid)
        converter.CONFIG["cred"] = (
            self.manager_for(aid, item) if item and item["enabled"] else None
        )

    # ── 密钥 / 会话 / 鉴权（与 Store 同形）──
    def add_key(self, name, value=None):
        from . import keysvc
        return keysvc.create_key(self, name, value=value)

    def check_api(self, authorization, x_api_key):
        """校验下游 API Key：返回命中的密钥条目（含 id / 策略），否则抛 401。"""
        from . import keysvc
        token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else x_api_key or ""
        with self.lock:
            if digest(token) in self.test_keys:
                return None
        key = keysvc.resolve_key(self, token)
        if not key:
            raise HTTPException(401, "invalid api key")
        keysvc.validate_credential(key)
        return key

    def require_admin(self, req):
        token = req.headers.get("X-Admin-Token", "")
        sid = token or req.cookies.get("workbuddy_admin", "")
        with self.lock:
            record = self.sessions.get(digest(sid))
            if not record or record["expires"] < time.time():
                raise HTTPException(401, "请先登录管理后台")
        # 头令牌凭「持有即证明」；cookie 鉴权需额外校验 CSRF。
        if not token and req.method not in ("GET", "HEAD"):
            if not hmac.compare_digest(req.headers.get("X-CSRF-Token", ""), record["csrf"]):
                raise HTTPException(403, "页面已失效，请重新登录")
        return record

    @staticmethod
    def validate_credential(doc):
        if not isinstance(doc, dict) or not isinstance(doc.get("auth"), dict) or not isinstance(doc.get("account"), dict):
            raise HTTPException(400, "需要桌面端 .info／JSON 登录文件，包含 auth 和 account 对象")
        if not isinstance(doc["account"].get("uid"), str) or not doc["account"]["uid"]:
            raise HTTPException(400, "凭据缺少 account.uid")

    def save_browser_account(self, doc, name=None):
        """把新的登录记录并入 switch 账号库（按 uid 去重）。"""
        account = doc.get("account") or {}
        auth = doc.get("auth") or {}
        uid = str(account.get("uid") or "")
        if not uid:
            raise HTTPException(400, "凭据缺少 account.uid")
        records = read_switch_accounts(self.accounts_path)
        entry = {
            "uid": uid,
            "nickname": account.get("nickname") or "",
            "enterpriseId": account.get("enterpriseId") or "",
            "note": name or "",
            "access_token": auth.get("accessToken", ""),
            "refresh_token": auth.get("refreshToken", ""),
            "expiresAt": auth.get("expiresAt") or 0,
            "refreshExpiresAt": auth.get("refreshExpiresAt") or auth.get("expiresAt") or 0,
            "domain": auth.get("domain") or DEFAULT_DOMAIN,
        }
        for i, rec in enumerate(records):
            if account_key(rec) == uid:
                # 命中已有记录时沿用它的 id（桌面端早年生成的随机 v4 也是合法 id，
                # 换成派生值会让那条记录的切换与会话绑定一起失效）。
                records[i] = {**rec, **entry, "id": accountid.ensure_account_id(rec)}
                break
        else:
            # 新记录必须带 id：桌面端 find_account 只认 id 或 uid，缺 id 的记录在
            # 切换时报「账号不存在」，要等桌面端下次刷新 token 补 id 才恢复。
            entry["id"] = accountid.derive_account_id(uid)
            records.append(entry)
        local_id = accountid.ensure_account_id(entry) or uid
        write_json(self.accounts_path, records)
        self.sync_from_switch()
        self.save()
        # 回传本地 id 而不是 uid：桌面端拿这个值去 find_account，uid 虽然也能命中，
        # 但界面上的账号列表、会话绑定用的都是本地 id，两套标识混用迟早出错。
        return {"account_id": local_id, "updated": True}
