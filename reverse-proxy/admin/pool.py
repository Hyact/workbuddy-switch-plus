"""Account-scoped billing, refresh, daily check-in and request routing."""
import asyncio
import hashlib
import json
import math
import os
import sys
import threading
import time
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

import httpx
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from . import alerts
from . import egress
from . import groups
from . import keysvc
from . import mirror
from . import realm as realm_mod
from . import report
from . import throttle
from . import travel
from . import usage
from . import wb2api
from .iputil import client_ip_from_scope

REQUEST_CREDENTIAL = ContextVar("pool_credential", default=None)
CN = timezone(timedelta(hours=8))
# billing 域基址随版本变（国际版是 www.workbuddy.ai），所以不再写死一个常量。
# 保留这两个名字只为兼容既有调用点与测试：它们现在指向**国内版**，新代码
# 一律用 realm.billing_url(path, realm)。
BILLING = "https://www.codebuddy.cn/v2/billing/meter/"
# 企业配额接口：企业账号不走个人版资源接口，官方按 `enterpriseId` 分流到这里；
# 国内版与国际版路径同构（与桌面端 credits.rs 的 ENTERPRISE_USAGE_PATH 同值）。
ENTERPRISE_USAGE = "https://www.codebuddy.cn/v2/billing/meter/get-enterprise-user-usage"


def enterprise_id_of(headers) -> str:
    """从请求头里取企业 ID（账号是企业版时非空）。

    请求头由 switch_store 的鉴权链路统一注入：企业账号会同时带
    `X-Enterprise-Id` 与 `X-Tenant-Id`，个人账号两个都不带。
    """
    if not headers:
        return ""
    for key in ("X-Enterprise-Id", "X-Tenant-Id"):
        value = headers.get(key) if hasattr(headers, "get") else None
        if value:
            return str(value).strip()
    return ""


def parse_enterprise_usage(payload):
    """解析企业配额响应 → (limit_num, used, cycle_reset_at) 或 None。

    兼容 `{data:{data:{…}}}` / `{data:{…}}` / 字段直接在顶层三种包装，
    以及 camelCase 与 snake_case 两种命名（官方两处实现各用一种）。
    总量缺失或非有限数字视为解析失败，由调用方给出可读错误。
    """
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    nested = data.get("data") if isinstance(data.get("data"), dict) else {}
    for candidate in (nested, data, payload):
        if not isinstance(candidate, dict):
            continue
        limit_num = _first_number(candidate, ("limitNum", "limit_num"))
        if limit_num is None:
            continue
        used = _first_number(candidate, ("credit", "used_num")) or 0.0
        used = max(0.0, used)
        reset = _first_value(candidate, ("cycleResetTime", "CycleResetTime"))
        return limit_num, used, _parse_reset_time(reset)
    return None


def _first_number(payload, keys):
    for key in keys:
        if key in payload:
            try:
                v = payload[key]
                if isinstance(v, bool):
                    continue
                n = float(v)
            except (TypeError, ValueError):
                continue
            if math.isfinite(n):
                return n
    return None


def _first_value(payload, keys):
    for key in keys:
        if payload.get(key) not in (None, ""):
            return payload[key]
    return None


def _parse_reset_time(value):
    """周期重置时间 → datetime，解析不出来返回 None（不阻塞展示）。"""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        n = float(value)
        if not math.isfinite(n) or n <= 0:
            return None
        # 毫秒与秒都接受：大于 1e11 视为毫秒（约 1973 年以后）。
        seconds = n / 1000.0 if n > 1e11 else n
        try:
            return datetime.fromtimestamp(seconds, CN)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=CN)
        except ValueError:
            continue
    return None

# 签到日志上限：只留最近这些条，落盘在 state.json 里。
CHECKIN_LOG_LIMIT = 500
# ── 请求日志的两条上限，职责完全不同，不要混 ──────────────────────────
#
# 业务规则（用户要的）：日志只保留 30 天，超期从磁盘删掉。
#   用户原话「默认保存日志内容为一个月内的 超出会自动删除」。
#   注意「删除」是字面意思：不是查询时不过滤掉，是不再占用磁盘。
#   判据用 `<`（见 _parse_log_time）：正好 30 天的那一条保留。
#   选 `<` 不选 `<=` 的理由：`<=` 会让「边界那一条」取决于浮点/取整，
#   而 `<` 只需比较两个整数，行为在任何机器上都一致；
#   差一秒的那条落进 30 天内、被保留 —— 这是「宁可多留一秒」的保守侧。
REQUEST_LOG_RETENTION_DAYS = 30
REQUEST_LOG_RETENTION_SECONDS = REQUEST_LOG_RETENTION_DAYS * 86400
#
# 防爆保护（与业务规则无关）：内存里最多屯这么多条。
#   去掉这个上限，一个疯狂打请求的进程能把内存吃光。
#   它故意比 30 天能攒下的量宽松，所以正常情况下永远不会触发 ——
#   触发只说明「有人在狂刷」，不是「30 天到了」。
#   5000 条 ≈ 1.5 MB 内存（每条约 300 B），是安全的量级。
REQUEST_LOG_MEMORY_LIMIT = 5000
#
# 落盘后文件超过这么多行才重写一次。攒着批量裁，避免每条都重写整个文件。
REQUEST_LOG_COMPACT_THRESHOLD = 1000
# 上游 /status 的缓存时长。面板几秒刷一次，上游要跨网络，没必要每次都读；
# 但冷却剩余时间是要「看着动」的，所以也不能太长——5 秒比一次请求便宜得多，
# 又不至于让倒计时明显跳步。
UPSTREAM_TTL = 5.0
# 全池闸门顶满时，请求最多让出事件循环重试几次、每次等多久。
# 5 × 0.05s = 250ms 上限：够等到一个在途请求收尾，又不至于让上游开始
# 对我们自己超时。等不到就兜底放行（见 acquire 的注释）。
GATE_RETRIES = 5
GATE_RETRY_DELAY = 0.05
DEFAULT_POOL = {
    "routing": "round_robin",
    "auto_checkin": True,
    "checkin_time": "09:00",
    # 派猫猫旅行：默认关闭。它会对账号发起真实写请求（派发 + 领奖），
    # 与签到那种「一天一次、失败也无副作用」的动作不是一个量级，
    # 所以不跟着 auto_checkin 一起默认打开。
    "auto_travel": False,
    "travel_time": "08:30",
    # 保活：token 剩余寿命少于这么多小时就提前刷一次。
    # 不设的话，账号只在「恰好被请求打到」时才刷新——池子里长期没人用的号
    # 会一路放到过期，等真要用时才发现只能重新登录。
    "auto_keepalive": True,
    "keepalive_hours": 6,
    # 对话活跃上报：一份 chat_request_send 事件，点亮 growth 连登并解锁
    # 领养猫的前置对话量。默认关闭——它是对上游的一次写入（虽然幂等），
    # 和旅行一样属于「要用户明确点头才做」的动作。
    # active_reports：每号每天发几条，5 条用于补满「领养需 5 次对话」的门槛。
    "auto_active": False,
    "active_time": "10:00",
    "active_reports": 1,
    # 上游 workbuddy2api 的接入点：配了就去读它 /status 里模型级的真实冷却，
    # 没配（或读不到）就退回我们自己按错误码估的 cooldown_until。
    # 默认空 = 不读。理由：本机默认并没有跑 workbuddy2api（默认 7863 拒绝连接），
    # 默认开会让每次刷新都白等一个超时，还会在界面上摆一个永远读不到的来源。
    "wb2api_base": "",
    "wb2api_key": "",
    # 调度方式：
    #   round_robin  轮流用（默认，把请求摊到所有可用账号上）
    #   manual       只用「当前账号」这一个，绝不切到别的号
    #   least_used   每次挑累计请求数最少的号
    # spread 是可选增强：开启后轮到哪个号就把它钉住一段时间（见 spread_minutes），
    # 走完这一段时间再换下一个。用来控制「同一账号在短时间内被连续调用」的量。
    "spread": False,
    "spread_minutes": 30,
    # ── 账号级流量整形的**默认值** ──
    #
    # 三项都是「新加账号时抄一份到这个号上」，账号自己填了就按账号的算。
    # 之所以给默认值而不是让用户一个个设：池子有几十个号的时候，
    # 一个个点开设是不现实的，绝大多数人只会想要「全池都一样」。
    #
    # 默认值必须让行为与改造前完全一致：
    #   weight 1      等权（≠0，0 表示不参与自动轮转）
    #   max_concurrency 0  不限制
    #   min_interval  0  不限速
    "default_weight": 1.0,
    "default_max_concurrency": 0,
    "default_min_interval": 0.0,
    # ── 全池总并发上限 ──
    #
    # 账号级 max_concurrency 治不了「每个号都没超、但同一时刻整体太猛」：
    # 20 个号 × 每号 3 并发 = 60 个请求同时打到上游，从单个号看全都合规，
    # 从风控看却是 20 个账号在同一瞬间一起活跃。这一项是给整体加一道闸。
    #
    # 默认 0 = 不限制，与改造前完全一致。它让请求**排队**，不让它们失败。
    "max_total_concurrency": 0,
    # ── 镜像加速（重试 / 退避）──
    #
    # 上游偶发 5xx 和连接重置，在池里表现为「这个账号挂了」→ 冷却 → 换号 → 告警，
    # 实际多数是几百毫秒内的瞬时故障。打开这一项后，这类失败会先重试再判死。
    #
    # **默认关闭**：重试会放大上游压力，配置项存在不等于应该打开。
    # `retry_attempts` 是**总尝试次数**（含第一次），0 与「关闭」等价。
    "retry_enabled": False,
    "retry_attempts": 0,
    "retry_backoff": 0.0,
}


def default_pool():
    return dict(DEFAULT_POOL)



def number(value):
    if isinstance(value, bool):
        raise ValueError("invalid number")
    try:
        n = Decimal(str(value))
    except InvalidOperation:
        raise ValueError("invalid number")
    if not n.is_finite():
        raise ValueError("invalid number")
    return max(Decimal(0), n)


def summarize_packages(packages):
    remain = Decimal(0)
    size = Decimal(0)
    for p in packages:
        # Precise values carry fractional credit balances; cycle values are spendable now.
        prefix = "Cycle" if any(k in p for k in ["CycleCapacityRemainPrecise", "CycleCapacityRemain"]) else ""
        def field(name, default=None):
            return p.get(prefix + name + "Precise", p.get(prefix + name, default))
        r = number(field("CapacityRemain"))
        capacity = number(field("CapacitySize", r))
        remain += min(r, capacity) if capacity else r
        size += capacity
    return {"remaining": float(remain), "capacity": float(size), "used": float(max(Decimal(0), size - remain)), "packages": len(packages)}


def _clock_hm(value, fallback="00:00"):
    """把 `HH:MM` 归一化成能安全做字符串比较的形态。

    调度闸门全是 `now_hm >= active_time` 这种**字符串**比较（`now_hm` 由
    `strftime("%H:%M")` 给出，永远是补零的两位）。一旦配置那一侧不是补零的
    两位——`"9:00"`、空串、`None`——比较结果就不再是「时间先后」，而是
    「字典序」，而且方向是**永远不开闸**：`"10:00" < "9:00"` 为真，所以
    `active_time="9:00"` 会让这个功能一整天一个账号都不派，且完全静默
    （界面显示开着、流水里一条记录都没有）。

    server.py 的 PATCH 有正则挡着新写入，但 state.json 是人手能改的、
    旧版本也可能写坏。所以判据要能吞掉坏数据，而不是相信它。
    """
    text = str(value if value is not None else "").strip()
    if len(text) == 5 and text[2] == ":" and text[:2].isdigit() and text[3:].isdigit():
        hours, minutes = int(text[:2]), int(text[3:])
        if 0 <= hours <= 23 and 0 <= minutes <= 59:
            return text
    return fallback


def _stamp(value):
    """把 state.json 里读回来的时间戳折成 int。坏了就当成 0（= 从没试过）。

    这些值是人手能改、也会被旧版本写坏的落盘数据。让 int() 在闸门里抛，等于
    调度每个 tick 都炸一次——而且炸的是 tick，不是某一次操作，现象是「所有自动
    任务一起停了」。所以判据要能吞掉坏数据，不是相信它。
    """
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


class BillingError(Exception):
    def __init__(self, message, status=502, code=None):
        super().__init__(message)
        self.status, self.code = status, code


# 账号动作 → 任务流水类别。没列进来的动作（status）不记流水：它只是读一次积分，
# 记下来会把真正的签到 / 旅行记录淹掉。
ACTION_KINDS = {"checkin": "checkin", "refresh": "keepalive",
                "travel": "travel", "travel-claim": "travel",
                "active": "active"}

# 任务流水的类别白名单。它同时是三处的唯一出处：server.py 的
# `pool/checkin-logs/clear?kind=` 校验、网页后台与桌面端两套界面的筛选项。
# 各写一份的后果是「某一个类别清不掉」——400 退回来，而界面照旧把它列在下拉里。
TASK_KINDS = ("checkin", "travel", "keepalive", "active")

# 旅行的两个节拍，与桌面端 travel.rs 的常量对齐：
#   · 派发重试 —— 30 分钟一轮（只对「可重试」的失败重试，当日名额用完就不再来）
#   · 领奖对账 —— 15 分钟一轮（到点了才回查官方状态）
TRAVEL_RETRY_SECONDS = 30 * 60
TRAVEL_CLAIM_SECONDS = 15 * 60
# 活跃上报失败后的重试节拍。它按天幂等，所以失败不必当轮纠缠——但**也不该
# 当成当天已完成**：失败（含「上报 200 但被静默丢弃」）会按这个节拍重试到当天结束。
ACTIVE_RETRY_SECONDS = 30 * 60
# 只会在当天有效的终局跳过原因：命中之后当天不再重试。
# 国际版账号就是这一类——它的计费域与国内不同，我们这里发的国内主机对它
# 必然失败，且不会因为重试而变好。不挡的话，它会每 30 分钟往 500 条上限的
# 任务流水里塞一条同样的失败记录，把真正有用的签到 / 旅行记录挤出去。
# （旅行的 RETRYABLE_SKIPS 是同一件事，只是那边用 skip 字符串分类。）
ACTIVE_TERMINAL_SKIPS = frozenset({"intl"})
# 单次 tick 最多处理几个账号：一轮里打出一串同源请求，风控信号比分散开难看。
# 现在由三类自动任务共用（派旅行 / 活跃上报 / 凭据保活），不只是旅行。
AUTO_BATCH_PER_TICK = 5
# 旧名保留：它是这一族常量的第一个名字，测试与调用方都在用。
TRAVEL_BATCH_PER_TICK = AUTO_BATCH_PER_TICK
# 保活巡检节拍：每个账号最多这么频繁地去读一次凭据到期时间。
KEEPALIVE_CHECK_SECONDS = 10 * 60


class AccountPool:
    def __init__(self, store, clock=time.time, client_factory=None):
        self.store, self.clock = store, clock
        self.client_factory = client_factory or (lambda **kw: httpx.Client(timeout=20, follow_redirects=False, **kw))
        self.locks = {}
        self.cursor = 0
        self.jobs = asyncio.Lock()
        self._log_lock = threading.Lock()
        self.last_sync = 0
        # 请求日志：谁（哪个账号）用了哪个模型、扣了多少。
        #
        # 内存环形缓冲 + 本地文件持久化（JSONL，按时间保留 30 天，见文件头常量）：
        # deque 一重启就空了，用户看到「日志全没了」，而排查问题恰恰经常是
        # 「重启之后想看看上次崩之前发生了什么」。
        # 选 JSONL 而不是塞进 state.json：日志是追加写的高频数据，
        # 混进 state.json 会导致每次记一条日志就重写整份状态文件。
        # 上限用「防爆」那个常量，不是业务规则那个 —— 30 天是业务规则，
        # 内存上限只是别让狂刷的进程把内存吃光。见文件头常量处的说明。
        self.request_log = deque(maxlen=REQUEST_LOG_MEMORY_LIMIT)
        self._log_path = self._resolve_log_path(store)
        self._load_request_log()
        # 用量聚合（usage_stats）改了但还没落盘。不逐请求写盘——那份分桶表比 state.json
        # 的其它部分大，每个请求重写一遍不划算。由 tick() 每分钟兜一次底，见 flush_usage()。
        self.usage_dirty = False
        with store.lock:
            settings = store.data.setdefault("pool", {})
            for key, value in DEFAULT_POOL.items():
                settings.setdefault(key, value)
            store.data.setdefault("account_status", {})
            store.data.setdefault("session_bindings", {})
            store.data.setdefault("checkin_logs", [])
            # 旅行状态按账号存：它是有状态的（traveling 要等 arrive_at、arrived 才领奖），
            # 不像签到那样一个日期字符串就够。
            store.data.setdefault("travel_states", {})
            store.data.setdefault("usage_stats", usage.default_usage_stats())
            # 分组与出口线路是这一版新增的两块账号运营数据。在这里 setdefault
            # 一次，读的地方（groups.resolve / egress.proxy_for）就可以直接取，
            # 不必到处写 `or {}`——漏一处就是一次 KeyError。
            store.data.setdefault("groups", {})
            store.data.setdefault("egress", egress.default_egress())
            settings["lease"] = None
            store.save()

    def flush_usage(self) -> bool:
        """把内存里的用量聚合落盘；没有待写内容时是空操作。返回是否写了盘。"""
        if not self.usage_dirty:
            return False
        with self.store.lock:
            self.store.save()
            self.usage_dirty = False
        return True

    def client_for(self, aid):
        """账号面请求（积分 / 签到）用的客户端：带上该账号的出口线路。

        有出口才传 `proxy=` —— 没出口时保持一次「无参调用」，这样测试里注入的
        裸 `lambda: FakeClient()` 不会被关键字参数绊倒，也避免显式 `proxy=None`
        把 HTTP_PROXY 环境变量代理关掉。
        """
        url = egress.proxy_for(self.store, aid)
        return self.client_factory(**({"proxy": url} if url else {}))

    def operation_lock(self, aid):
        with self.store.lock:
            return self.locks.setdefault(aid, threading.Lock())

    def snapshot(self, aid):
        with self.store.lock:
            item = self.store.data["accounts"].get(aid)
            if not item:
                raise HTTPException(404, "账号不存在")
            return dict(item), dict(self.store.data["account_status"].get(aid, {}))

    def update(self, aid, **values):
        with self.store.lock:
            if aid in self.store.data["accounts"]:
                self.store.data["account_status"].setdefault(aid, {}).update(values)
                self.store.save()

    def log_task(self, aid, kind, ok, message, source="manual", credits=None):
        """追加一条任务流水（签到 / 旅行 / 保活）。

        以前只在 account_status[aid]["checkin_date"] 里存一个日期字符串，
        出了问题（今天到底签没签、哪一步报的错）完全没法回溯。
        这里落一份有上限的流水，成功失败都记。

        `kind` 是后加的：原先只有签到，字段就叫 checkin_logs / log_checkin。
        旅行和保活接进来以后，同一份流水要能区分来源，否则界面上只能看到
        一堆「成功」，分不清是签到了还是派上旅行了。落盘键名保持 checkin_logs
        不变——改名要迁移历史数据，而它只是个上限 500 条的流水。
        """
        with self.store.lock:
            name = (self.store.data["accounts"].get(aid) or {}).get("name") or aid
            logs = self.store.data.setdefault("checkin_logs", [])
            entry = {"time": int(self.clock()), "id": aid, "name": name,
                     "kind": kind, "ok": bool(ok),
                     "message": str(message or "")[:200], "source": source}
            if credits is not None:
                entry["credits"] = credits
            logs.append(entry)
            if len(logs) > CHECKIN_LOG_LIMIT:
                del logs[: len(logs) - CHECKIN_LOG_LIMIT]
            self.store.save()

    def log_checkin(self, aid, ok, message, source="manual"):
        self.log_task(aid, "checkin", ok, message, source)

    def task_logs(self, limit=200, kind=None):
        """任务流水，新的在前。`kind` 为空时返回全部类型。"""
        with self.store.lock:
            logs = list(self.store.data.get("checkin_logs", []))
        if kind:
            logs = [row for row in logs if (row.get("kind") or "checkin") == kind]
        logs.reverse()
        return logs[: max(1, min(CHECKIN_LOG_LIMIT, int(limit)))]

    def checkin_logs(self, limit=200):
        return self.task_logs(limit)

    def task_summary(self, hours=24):
        """按类别汇总任务流水：每类成功/失败多少、最近一次是什么时候。

        为什么需要它：`task_logs()` 只给"最近 200 条明细"，翻起来很不直观——
        「签到今天到底签了几个号成功几个」得自己数。这里直接给答案。

        窗口按**自然时间**切（`hours` 小时前到现在），不是"最近 N 条"：
        后者在任务跑得少的时候会把昨天的事也算进"今天"。
        """
        with self.store.lock:
            logs = list(self.store.data.get("checkin_logs", []))
        # 注意 `or` 会把显式的 0 吃掉回落到 24：这里的语义是"窗口至少 1 小时"，
        # 传 0 应当被夹到 1，而不是悄悄变成一整天。
        try:
            window = int(hours)
        except (TypeError, ValueError):
            window = 24
        window = max(1, window)
        since = int(self.clock()) - window * 3600
        rows = {}
        for kind in TASK_KINDS:
            rows[kind] = {"kind": kind, "total": 0, "ok": 0, "failed": 0, "last": None}
        for row in logs:
            if int(row.get("time") or 0) < since:
                continue
            kind = row.get("kind") or "checkin"
            slot = rows.get(kind)
            if slot is None:      # 未来新增的类别也不会被吞掉
                slot = rows[kind] = {"kind": kind, "total": 0, "ok": 0,
                                     "failed": 0, "last": None}
            slot["total"] += 1
            if row.get("ok"):
                slot["ok"] += 1
            else:
                slot["failed"] += 1
            slot["last"] = max(slot["last"] or 0, int(row.get("time") or 0))
        out = list(rows.values())
        for slot in out:
            slot["success_rate"] = round(slot["ok"] / slot["total"], 4) if slot["total"] else 0.0
        return {"hours": window, "kinds": out}

    def clear_task_logs(self, kind=None):
        """清空任务流水；给了 kind 只清那一类。返回清掉的条数。"""
        with self.store.lock:
            logs = self.store.data.get("checkin_logs", [])
            if kind:
                kept = [row for row in logs if (row.get("kind") or "checkin") != kind]
                removed = len(logs) - len(kept)
                self.store.data["checkin_logs"] = kept
            else:
                removed = len(logs)
                self.store.data["checkin_logs"] = []
            self.store.save()
        return removed

    def clear_checkin_logs(self):
        return self.clear_task_logs()

    def state(self, row):
        status = self.store.data["account_status"].get(row["id"], {})
        if not row["enabled"]:
            return "paused"
        if row["status"] == "invalid" or status.get("auth_invalid"):
            return "invalid"
        if status.get("cooldown_until", 0) > self.clock():
            return "cooling"
        if status.get("credits_updated", 0) > self.clock() - 600 and status.get("remaining") == 0 and status.get("packages", 0) > 0:
            return "exhausted"
        return "available"

    def rows(self, rows):
        today = datetime.fromtimestamp(self.clock(), CN).strftime("%Y-%m-%d")
        with self.store.lock:
            states = dict(self.store.data.get("travel_states") or {})
        # 上游冷却只读一次，给整批账号用（不是每行读一次）。
        # 没配 / 读不到时是空 dict，下面每行的 up_ 字段就全是 None——
        # 界面据此完全不显示这一块，而不是显示成「没有冷却」。
        upstream = self.upstream_cooldowns()
        for row in rows:
            status = self.store.data["account_status"].get(row["id"], {})
            travel_state = states.get(row["id"]) or {}
            row.update({"pool_state": self.state(row), "remaining": status.get("remaining"), "credits_updated": status.get("credits_updated"),
                        "credits_stale": status.get("credits_updated", 0) < self.clock() - 600,
                        "today_checked_in": status.get("checkin_date") == today, "cooldown_until": status.get("cooldown_until", 0),
                        "last_error": status.get("last_error"), "token_refreshed": status.get("token_refreshed"),
                        "request_count": status.get("request_count", 0),
                        # 旅行卡片要的展示值：今天派没派、在途与否、到点没到点、领了多少。
                        # `same_day` 为假表示这是上一次行程的残留（还没领到手），
                        # 前端据此显示「旅行中」而不是「今日已派」。
                        "travel_label": self.travel_label(travel_state, today),
                        "travel_same_day": travel_state.get("date") == today,
                        "travel_location": travel_state.get("locationName"),
                        "travel_arrive_at": travel_state.get("arriveAt"),
                        "travel_reward": travel_state.get("rewardCredit"),
                        "travel_skip": travel_state.get("skip"),
                        # 活跃上报的展示值。口径与 today_checked_in 一致——判据就是
                        # 「本地记的日期是不是今天」。三个字段一起给：前端要能区分
                        # 「今天报过」「今天没报但以前报过」「从来没报过」。
                        "active_date": status.get("active_date"),
                        "active_today": status.get("active_date") == today,
                        "active_streak": status.get("active_streak"),
                        # 上一次失败 / 「报了但没生效」的原因。这个字段存在的唯一
                        # 理由就是排查「这号为什么一直没点亮」，而界面的数据源是
                        # rows()——不透出去就只能靠人翻 state.json。
                        "active_error": status.get("active_error"),
                        # 当天有效的终局跳过（如国际版账号）。界面据此说明
                        # 「今天不会再试了」，而不是显示成一条待重试的失败。
                        "active_skip": (status.get("active_skip")
                                        if status.get("active_skip_date") == today else None),
                        # 积分快照（只读）要用到这三个字段：它们由 check_credits 落进
                        # account_status，但以前没透出到 rows()，所以看板只能拿到 remaining。
                        # 这里补齐，让「容量 / 已用 / 套餐数」也能被对账脚本读到。
                        "capacity": status.get("capacity"), "used": status.get("used"),
                        "packages": status.get("packages"),
                        # ── 账号级流量整形（见 admin/throttle.py）─────────────
                        # 三项都为 0 表示不限制，界面据此显示「不限」而不是「0」。
                        # `weight` 缺省展示成 1：0 是「不参与轮转」的显式语义，
                        # 不能拿它冒充「没配」。
                        "weight": throttle.effective_weight(status),
                        "max_concurrency": throttle.limits_of(status)["max_concurrency"],
                        "min_interval": throttle.limits_of(status)["min_interval"],
                        "inflight": throttle.inflight(status),
                        # 连续失败次数：界面据此把「偶发抖动」和「快被封了」分开显示。
                        "consecutive_fails": int(status.get("consecutive_fails") or 0),
                        "last_fail_at": status.get("last_fail_at")})
            # ── 上游 workbuddy2api 的权威冷却（模型级）──────────────────────
            # 只在这号确实在上游状态里出现过时才填。匹配用 uid——
            # 对不上就什么都不说，绝不能把别的账号的冷却安到这个号头上。
            up = upstream.get(str(row.get("uid") or ""))
            row.update({
                "up_cooling": bool(up.get("cooling")) if up else None,
                "up_cool_remaining": up.get("cool_remaining_sec") if up else None,
                "up_reason": (up.get("reason") or None) if up else None,
                "up_until": up.get("until") if up else None,
                # 模型级台账：每行 {model, until, reset_at, remaining_sec, reason}。
                # 这是这个功能的核心——账号级冷却说不出「哪个模型、几点恢复」。
                "up_models": (up.get("rate_limited_models") or []) if up else [],
                "up_consecutive_fails": up.get("consecutive_fails") if up else None,
                "up_degrade_until": up.get("degrade_until") if up else None,
                "up_disabled": up.get("disabled") if up else None,
                "up_manual_disabled": up.get("manual_disabled") if up else None,
            })
        return rows

    @staticmethod
    def travel_label(state, today):
        """旅行卡片的展示档位，与桌面端 travel.rs 的 display_label 同口径：

        `traveling` 旅行中 / `no-buddy` 无 Buddy / `finished` 已结束（含当日名额用完）
        / `untraveled` 未旅行。跨日还没领到手的行程仍然显示「旅行中」——
        它确实还在路上，不该因为过了零点就变成「未旅行」。
        """
        if travel.result_in_flight(state):
            return "traveling"
        same_day = (state or {}).get("date") == today
        if same_day and state.get("skip") == "no-buddy":
            return "no-buddy"
        if same_day and travel.result_claimed(state):
            return "finished"
        return "untraveled"

    def _pick(self, candidates, now, affinity_key, routing=None):
        """在候选账号里挑一个。所有调度策略都汇总在这里。

        返回 (aid, 是否命中会话黏性)。

        `routing` 是**分组级覆盖**（见 admin/groups.py）：某个分组配了自己的
        调度方式时用它，否则用全局设置。
        """
        pool = self.store.data["pool"]
        routing = routing or pool.get("routing", "round_robin")
        bindings = self.store.data["session_bindings"]
        ids = {row["id"] for row in candidates}

        # 1) session_bindings 最高优先级：同一会话尽量落在同一账号上，
        #    否则 prompt cache 每次都落空，既费钱又慢。
        bound = bindings.get(affinity_key, {}).get("account_id")
        if bound in ids:
            return bound, True

        # 2) spread（轮换驻留）：把当前账号钉住 spread_minutes 分钟再换下一个。
        #    这是控制「单账号短时间被高频调用」的主要旋钮。
        if pool.get("spread"):
            lease = pool.get("lease") or {}
            lease_id = lease.get("account_id")
            if lease_id in ids and lease.get("until", 0) > now:
                return lease_id, False

        # 3) 选新号
        #
        # 这一步以前是「least_used 取最少 / 否则游标轮流」。现在多了账号级
        # 流量整形（见 admin/throttle.py）：权重、并发上限、最小间隔。
        # 三项都为 0 时行为与改造前完全一致——这是升级兼容的硬要求，
        # 存量 state.json 里没有任何这些字段。
        statuses = self.store.data["account_status"]
        # 拆成两组：能立刻发的、以及被并发/间隔卡住的。
        ready = [row for row in candidates if not throttle.penalty(statuses.get(row["id"], {}), now)[0]]
        # 全都被卡住时不能在两个组里二选一了事：宁可挑「欠账最少」的那个放过去，
        # 也不报「暂无可用账号」——那样用户会以为服务挂了，实际是自己把自己限死。
        pool_rows = ready or candidates

        if routing == "least_used":
            # 累计请求数最少的优先；相同则按 id 稳定排序，避免随机抖动。
            aid = min(pool_rows, key=lambda row: (statuses.get(row["id"], {}).get("request_count", 0), row["id"]))["id"]
        else:
            # 轮流：先按权重展开成确定性序列，再用游标取。
            order = throttle.weighted_order(pool_rows, statuses, self.cursor)
            if order:
                aid = order[0]
                self.cursor += 1
            else:  # pragma: no cover - weighted_order 在非空输入下不会返回空
                aid = pool_rows[self.cursor % len(pool_rows)]["id"]
                self.cursor += 1

        if pool.get("spread"):
            minutes = max(1, int(pool.get("spread_minutes", 30)))
            pool["lease"] = {"account_id": aid, "until": now + minutes * 60}
            self.store.save()
        return aid, False

    def select(self, affinity_key=None, key=None):
        """挑一个账号；`key` 是发起请求的密钥，用来做分组约束（可为 None）。

        过滤顺序有讲究：**先按分组缩范围，再叠手动模式**。反过来会让
        「手动模式钉住的账号不在密钥分组里」这种配置报出「账号不可用」，
        而真实原因是密钥压根不该用那个号——报错指错方向比不报错更费时间。
        """
        # 分组只看密钥；密钥缺席（测试请求 / 无鉴权部署）= 不限制。
        allowed, routing_override = groups.resolve(self.store, key)
        with self.store.lock:
            candidates = [row for row in self.store.account_rows() if self.state(row) == "available"]
            if allowed is not None:
                candidates = [row for row in candidates if row["id"] in allowed]
                if not candidates:
                    gids = (key or {}).get("groups") or []
                    if allowed == set():
                        raise HTTPException(503, "该密钥绑定的分组已全部停用：请在分组设置里启用，或解除密钥的分组绑定")
                    raise HTTPException(503, f"该密钥绑定的分组（{len(gids)} 个）里暂无可用账号：请检查分组内的账号是否暂停、积分耗尽或登录失效")
            if self.store.data["pool"].get("routing") == "manual":
                # 手动模式：只用「当前账号」，绝不轮到别的号。
                candidates = [row for row in candidates if row["id"] == self.store.data["active"]]
                if not candidates:
                    raise HTTPException(503, "当前账号不可用：请在账号池里换一个账号，或改回轮流使用")
            # 国际版账号默认不进对话轮转：workbuddy.ai 网关对非官方客户端做
            # 「渠道校验」，一律回 11128「这次调用没通过渠道校验，可能不是官方
            # 客户端发出的」。放进轮转只会走成「选中 → 401/11128 → 冷却 5 分钟
            # → 这次请求失败」，还把本来能用的国内号挤掉了。
            # 积分与签到不受影响（各自按 realm 分域走 billing）。
            # 想放回来：把 state.json 里 pool.chat_include_global 设为 true。
            if not self.store.data["pool"].get("chat_include_global"):
                candidates = [row for row in candidates if row.get("realm") != "global"]
            if not candidates:
                raise HTTPException(503, "暂无可用账号：请检查暂停、积分、冷却或登录状态")
            now = self.clock()
            bindings = self.store.data["session_bindings"]
            # 注意别用 `key` 作循环变量：那会覆盖上面那个「发起请求的密钥」参数。
            for stale in list(bindings):
                if bindings[stale].get("expires", 0) <= now:
                    del bindings[stale]
            aid, sticky = self._pick(candidates, now, affinity_key, routing_override)
            if affinity_key and not sticky:
                if affinity_key not in bindings and len(bindings) >= 4096:
                    del bindings[min(bindings, key=lambda key: bindings[key]["expires"])]
                bindings[affinity_key] = {"account_id": aid, "expires": now + 86400}
            item = self.store.data["accounts"][aid]
            return aid, self.store.manager_for(aid, item)

    def record(self, aid, status=200):
        with self.store.lock:
            if aid not in self.store.data["accounts"]:
                return
            data = self.store.data["account_status"].setdefault(aid, {})
            data["request_count"] = data.get("request_count", 0) + 1
            data["last_request"] = int(self.clock())
            # 连续失败计数：认输的号和偶发抖动的号要分开对待。
            # 只有「上游真的拒绝了」才计；客户端自己取消 / 超时不在此列
            # （那些是本地网络问题，算到账号头上会误伤）。
            if status in (401, 402, 403, 429):
                fails = int(data.get("consecutive_fails") or 0) + 1
                data["consecutive_fails"] = fails
                data["last_fail_at"] = int(self.clock())
            elif status == 200:
                if data.get("consecutive_fails"):
                    data["consecutive_fails"] = 0
            if status in (401, 403):
                data.update(cooldown_until=self.clock() + 300, last_error="上游认证或访问被拒绝，已冷却 5 分钟")
            elif status in (402, 429):
                data.update(cooldown_until=self.clock() + 1800, last_error="上游额度或频率限制，已冷却 30 分钟")
            self.store.save()

    # ── 账号级流量整形（并发 / 间隔）──────────────────────────────────
    def acquire(self, aid, ignore_gate=False):
        """占一个在途名额。返回 True 表示占到了。

        只是个计数，不是信号量：拿到 False 时调用方应该换号或后退，
        而不是阻塞等待——阻塞会把整个事件循环拖死。

        **两级判断，顺序不能反**：

        1. 池级总量闸门（`max_total_concurrency`）。它先于账号级判断，
           因为这一项的意义是限制「打到上游的总量」。如果先判账号级，
           每个号都会各自生效，闸门等于没有。
        2. 账号级 `max_concurrency`。

        `ignore_gate=True` 给后台任务（签到/旅行/保活）用：那些是每号
        一天一次的串行动作，不该和对话流量抢同一个闸门名额，否则用户配
        一个很小的上限时会连带把定时任务全部饿死。
        """
        with self.store.lock:
            if not ignore_gate:
                gate = throttle.pool_gate(self.store.data.get("pool"))
                if gate > 0:
                    total = throttle.total_inflight(self.store.data["account_status"])
                    if total >= gate:
                        return False
            data = self.store.data["account_status"].setdefault(aid, {})
            lim = throttle.limits_of(data)["max_concurrency"]
            cur = throttle.inflight(data)
            if lim > 0 and cur >= lim:
                return False
            data["inflight"] = cur + 1
            return True

    def release(self, aid):
        """归还在途名额。必须与 `acquire` 配对，且要放在 finally 里。

        计数只会减到 0，不会变负——服务重启时 `inflight` 是脏值（可能残留
        上次的计数），归零比精确减一更重要，否则账号会被永久判定为打满。
        """
        with self.store.lock:
            data = self.store.data["account_status"].get(aid)
            if not data:
                return
            cur = throttle.inflight(data)
            data["inflight"] = max(0, cur - 1)

    def set_limits(self, aid, weight=None, max_concurrency=None, min_interval=None):
        """设置账号级限制。传 None 表示「不动这一项」，不是「设成 0」。

        这个区分很重要：界面上改权重时不该把并发上限一起清掉。
        """
        with self.store.lock:
            if aid not in self.store.data["accounts"]:
                raise HTTPException(404, "账号不存在")
            data = self.store.data["account_status"].setdefault(aid, {})
            if weight is not None:
                data["weight"] = max(0, min(int(weight), throttle.MAX_WEIGHT))
            if max_concurrency is not None:
                data["max_concurrency"] = max(0, min(int(max_concurrency), throttle.MAX_CONCURRENCY))
            if min_interval is not None:
                data["min_interval"] = max(0.0, min(float(min_interval), throttle.MAX_MIN_INTERVAL))
            self.store.save()
            return {k: data.get(k, 0) for k in ("weight", "max_concurrency", "min_interval")}

    def log_request(self, aid, model, status, ok, tokens, credit, duration_ms, outcome, source="api", *,
                    first_token_ms=0, cached_tokens=0, upstream_model=None, key_id=None, key_hint=None,
                    key_name=None):
        """记一条请求日志：哪个账号、什么模型、花了多少。

        只有调度真正选中账号之后才会调用；`aid=None` 表示这一步就失败了
        （比如没有可用账号），此时也记一条，方便排查「为什么没通」。

        明细进内存环形缓冲（`request_log`），同时把这条调用汇进 `usage_stats` 的
        日/时桶（那一份会落盘，用来回答「这周哪几个模型在烧分」这类问题）。

        `model` 是客户端请求的名字，`upstream_model` 是别名映射后真正转发出去的名字——
        两者不同时，排查「明明选了 A 却在跑 B」就靠它俩对比。

        密钥三兄弟各管一段，**必须全存**：
          · `key_id`   —— 稳定标识，用来 join 分组、配额、IP 白名单
          · `key_name` —— 人给密钥起的名字，写日志时就固化下来
          · `key_hint` —— 密钥本身的脱敏片段（`sk-ab…1234`）

        `key_name` 刻意**冗余存一份**，而不是留给前端去 join `overview.keys`：
        密钥是可以被删的，删掉之后历史记录就再也说不出「当时是谁在用」了。
        日志是事后取证用的，不该依赖一个会被删的当前值。
        """
        if aid is None:
            name = None
        else:
            with self.store.lock:
                name = (self.store.data["accounts"].get(aid) or {}).get("name") or aid
        now = int(self.clock())
        entry = {
            "time": now,
            "account_id": aid,
            "account_name": name,
            "model": model or None,
            "upstream_model": upstream_model or None,
            "status": status,
            "ok": bool(ok),
            "tokens": int(tokens or 0),
            "credit": round(float(credit or 0), 6),
            # 首个非空响应分片到达的耗时。流式下约等于首字延迟。
            "first_token_ms": int(first_token_ms or 0),
            "cached_tokens": int(cached_tokens or 0),
            "duration_ms": int(duration_ms or 0),
            "outcome": outcome,
            "source": source,
            "key_id": key_id,
            "key_name": (str(key_name).strip() or None) if key_name else None,
            "key_hint": key_hint or None,
        }
        self.request_log.appendleft(entry)
        # 落盘一份，重启后还能看到（见 _load_request_log）。
        self._append_request_log(entry)
        with self.store.lock:
            # 吞吐统计只关心**模型自己出了多少字、花了多久吐**。
            # 失败请求的上游 body 常常带着半个 chunk 的 usage，把它当成 token 记进去，
            # 分母（gen_ms）却按"只算成功"处理，算出来的速率会被凭空抬高。
            # 聚合层的 tokens 记 0，请求日志里的原值照留 —— 那一份是用来对账的。
            usage.record(self.store, now=now, status=status,
                         tokens=tokens if ok else 0, credit=credit,
                         duration_ms=duration_ms, first_token_ms=first_token_ms,
                         model=upstream_model or model, key_id=key_id)
            self.usage_dirty = True

    # ── 请求日志持久化 ───────────────────────────────────────────────
    @staticmethod
    def _resolve_log_path(store):
        """日志文件位置：跟 state.json 放同一个数据目录。

        拿不到就退回 None（纯内存模式）—— 日志写不出去不该拖垮服务，
        但要让调用方知道「这次是内存模式」。
        """
        try:
            base = getattr(store, "path", None)
            if base is None:
                return None
            return Path(base).parent / "request-log.jsonl"
        except Exception:  # noqa: BLE001
            return None

    def _load_request_log(self) -> None:
        """启动时把 30 天内的记录读回内存。文件不存在 / 损坏都当「没有历史」。

        读之前先强制清理一次超期条目（见 `_prune_request_log_file`）——
        进程可能停机了很久，上次留下的记录早就该删了。
        """
        path = self._log_path
        if not path or not path.exists():
            return
        # 先清历史积压，再读 —— 进程上次退出时可能留下超期条目
        # （比如停机了一整个月没跑）。force 是因为此刻还没有「攒够阈值」的概念，
        # 而且启动只做这一次，成本可以忽略。清理失败不影响读回旧数据。
        try:
            self._prune_request_log_file(path, now=int(self.clock()), force=True)
        except OSError as exc:  # noqa: BLE001
            print(f"[reverse-proxy] 请求日志清理失败（{path}）：{exc}", file=sys.stderr)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print(f"[reverse-proxy] 请求日志读取失败（{path}）：{exc}", file=sys.stderr)
            return
        rows = []
        for line in lines[-REQUEST_LOG_MEMORY_LIMIT:]:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                # 半截行（上次写盘时被强杀）——跳过，不要让一条坏行废掉整份历史。
                continue
            if isinstance(item, dict):
                rows.append(item)
        # 文件是旧 → 新追加的；deque 用 appendleft，所以最新的要在最前。
        for item in reversed(rows):
            self.request_log.append(item)

    @staticmethod
    def _parse_log_time(value):
        """把日志条目的 `time` 解析成 epoch 秒（int）；解析不了返回 None。

        确认到的事实（不是假设）：
          · 写入点只有一处 —— `log_request` 里 `now = int(self.clock())`，
            所以正常记录**恒为 int 的 epoch 秒**。
          · 真实机器上现存 4 份 request-log.jsonl（含线上那份 121 KB / 300 行）
            抽样复核，`time` 全部是 `int`，无一是字符串或毫秒。
          · 但测试夹具 `wblogtest-*` 里出现过解析失败的行 ——
            所以**不能**假设它永远合法。

        因此这里接受「数字」与「数字字符串」两种，其余一律 None。
        毫秒（13 位）也可能来自将来手写/迁移的数据：
        按数量级判断并折算成秒，而不是直接当秒用 ——
        否则 13 位毫秒会被算成公元 5 万年，永远不被清理。
        """
        if isinstance(value, bool):
            # bool 是 int 的子类，但它显然不是一个时间戳。
            return None
        if isinstance(value, (int, float)):
            seconds = float(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                seconds = float(text)
            except ValueError:
                return None
        else:
            return None
        if not math.isfinite(seconds):
            return None
        # 13 位及以上当毫秒看待（epoch 秒到 13 位要等到公元 33658 年）。
        if abs(seconds) >= 1e11:
            seconds /= 1000.0
        return int(seconds)

    def _prune_request_log_file(self, path, *, now, force=False) -> int:
        """按 **30 天** 把文件里超期的行**真正删除**，返回删掉的行数。

        与「查询时过滤」的区别就是这次改动的全部要点：
        过滤只让返回值变短，文件照样无限长大；这里是真的不再占用磁盘。

        复杂度：本函数是 **O(n)**（读一次、写一次）。
        它只在「行数 > REQUEST_LOG_COMPACT_THRESHOLD」或 `force` 时被调用，
        所以**不是**每条日志都重写整个文件 ——
        否则就是 O(n²)：1000 条日志要写 1000 次文件。

        `force=True` 用于启动加载（那时正好顺手清一次历史积压）。
        裁剪结果**不会被回报成对外行为**：`request_logs(limit)` 仍然受 limit 约束。
        """
        if not path or not path.exists():
            return 0
        with self._log_lock:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return 0
            if not force and len(lines) <= REQUEST_LOG_COMPACT_THRESHOLD:
                return 0
            cutoff = now - REQUEST_LOG_RETENTION_SECONDS
            kept = []
            undecidable = 0
            for line in lines:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    # 半截行（上次被强杀）—— 丢掉，它本来也读不回来。
                    continue
                stamp = self._parse_log_time(item.get("time")) if isinstance(item, dict) else None
                if stamp is None:
                    # ⚠️ 解析不出时间的条目保留，不删。
                    # 删掉是不可恢复的，而我们并不确定它是否超期；
                    # 保留最坏只是多占一点磁盘，删错则是永久丢数据。
                    # 这种条目只会来自「外部手写 / 将来改格式」——正常写入路径
                    # 恒为 int epoch 秒，所以它出现即说明有异常，不该被静默清掉。
                    undecidable += 1
                    kept.append(line)
                    continue
                if stamp < cutoff:
                    continue          # 超期：真的不要了
                kept.append(line)
            if undecidable:
                # 保留归保留，但要说出来：静默保留会让人以为清理是完美工作的，
                # 而实际上有一批条目永远在文件里、永远不会被清理。
                print(f"[reverse-proxy] 请求日志有 {undecidable} 条无法判定时间的记录，"
                      f"已保留（不会删除）：{path}", file=sys.stderr)
            removed = len(lines) - len(kept)
            if not removed:
                return 0
            try:
                tmp = path.with_suffix(path.suffix + ".tmp")
                tmp.write_text("".join(l + "\n" for l in kept), encoding="utf-8")
                os.replace(tmp, path)
            except OSError as exc:
                print(f"[reverse-proxy] 请求日志裁剪失败（{path}）：{exc}", file=sys.stderr)
                return 0
        return removed
    def _append_request_log(self, entry: dict) -> None:
        """追加一条到文件，并把**超期**的行真正删掉。

        保留规则是**30 天**（业务规则，见文件头常量），不是「最近 N 条」。
        超期的行会被从文件里删除，所以文件不会无限增长。

        写入本身是 O(1) 追加；裁剪只在行数超过阈值时才发生，
        所以整体**不是** O(n²) —— 见 `_prune_request_log_file`。
        """
        path = self._log_path
        if not path:
            return
        try:
            with self._log_lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            # 攒到阈值才裁一次，避免每条日志都重写整个文件（那才是 O(n²)）。
            self._prune_request_log_file(path, now=int(self.clock()))
        except OSError as exc:
            # 日志是旁路：写不进去只提示，绝不让请求失败。
            print(f"[reverse-proxy] 请求日志写入失败（{path}）：{exc}", file=sys.stderr)

    def request_logs(self, limit=200):
        # limit 仍是对外契约里的上限，没变。这里改用防爆常量作为夹取上界 ——
        # 真实内存上限本来就是它，用 30 天去夹一个条数限制没有意义。
        return list(self.request_log)[: max(1, min(REQUEST_LOG_MEMORY_LIMIT, int(limit)))]

    def billing(self, client, headers, path, body=None, realm=None):
        """发一次 billing 请求。

        `realm` 决定 base（国内 www.codebuddy.cn / 国际 www.workbuddy.ai）。
        不传时按国内版——存量调用点全是国内版，这样升级不会改变既有行为。

        **为什么不从 headers 里推 realm**：X-Domain 只在国内版注入，
        国际版账号拿它推会落到国内版 base，是最隐蔽的一种错。
        """
        url = realm_mod.billing_url(path, realm) if realm else (BILLING + path)
        response = client.post(url, headers=headers, json=body or {})
        if response.status_code != 200:
            raise BillingError("积分服务请求失败", response.status_code)
        try:
            d = response.json()
        except ValueError:
            raise BillingError("积分服务返回格式异常")
        if not isinstance(d, dict) or d.get("code") != 0:
            raise BillingError("上游未接受该操作，请检查账号或稍后重试", code=d.get("code") if isinstance(d, dict) else None)
        return d.get("data")

    def credits(self, client, headers, realm=None):
        # 企业版分流：企业配额不在个人版资源接口里。官方按 `enterpriseId` 分流到
        # `get-enterprise-user-usage`，两版路径同构。必须先判，否则企业账号会
        # 查出一片空，界面显示成「没有积分」——用户会以为额度用光了。
        if enterprise_id_of(headers):
            return self._enterprise_credits(client, headers, realm)

        packages = []
        now = datetime.fromtimestamp(self.clock(), CN)
        for page in range(1, 101):
            d = self.billing(client, headers, "get-user-resource", {"PageNumber": page, "PageSize": 100, "ProductCode": "p_tcaca", "Status": [0, 3], "PackageEndTimeRangeBegin": now.strftime("%Y-%m-%d %H:%M:%S"), "PackageEndTimeRangeEnd": "2126-01-01 00:00:00"}, realm)
            try:
                data = d["Response"]["Data"]
                current = data["Accounts"]
                total = int(data["TotalCount"])
                if not isinstance(current, list) or total < 0:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise BillingError("积分数据格式异常，上次余额已保留")
            packages.extend(current)
            if len(packages) >= total:
                return summarize_packages(packages)
            if not current:
                break
        raise BillingError("积分包分页不完整，上次余额已保留")

    def _enterprise_credits(self, client, headers, realm=None):
        """企业配额查询：单次请求，输出与个人版同形（多一个 unlimited 标记）。"""
        url = (realm_mod.billing_url("get-enterprise-user-usage", realm)
               if realm else ENTERPRISE_USAGE)
        response = client.post(url, headers=headers, json={})
        if response.status_code != 200:
            raise BillingError("企业配额服务请求失败", response.status_code)
        try:
            d = response.json()
        except ValueError:
            raise BillingError("企业配额服务返回格式异常")
        code = d.get("code") if isinstance(d, dict) else None
        if code != 0:
            raise BillingError("上游未接受该操作，请检查账号或稍后重试", code=code)

        usage = parse_enterprise_usage(d)
        if usage is None:
            raise BillingError("企业配额数据无法解析")

        limit_num, used, reset_at = usage
        if limit_num == -1:
            # 不限量：数字字段置 None、资源列表为空。界面按 unlimited 分支展示，
            # 不写积分快照（0/0 快照会把统计页误显示成余额为 0）。
            return {
                "remaining": None,
                "capacity": None,
                "used": None,
                "packages": 0,
                "unlimited": True,
                "soonestExpireAt": None,
                "resources": [],
            }
        remaining = max(0.0, limit_num - used)
        expire_ms = int(reset_at.timestamp() * 1000) if reset_at else None
        return {
            "remaining": remaining,
            "capacity": limit_num,
            "used": used,
            "packages": 1,
            "unlimited": False,
            "soonestExpireAt": expire_ms,
            "resources": [{
                "packageName": "企业配额",
                "total": limit_num,
                "remaining": remaining,
                "used": used,
                "expireAt": expire_ms,
            }],
        }

    def checkin_status(self, client, headers, realm=None):
        """查签到状态。路径候选来自 `realm.billing_paths`，逐个试。

        两个历史路径（`checkin-activity-status` / `checkin-status`）并存是既有
        事实，这里只准备把它们当数据：以后上游再换路径，改 `realm.BILLING_PATHS`
        一处就够，不用回来改这里。
        """
        paths = realm_mod.billing_paths("checkin-status", realm) or (
            "checkin-activity-status", "checkin-status")
        last = None
        d = None
        for path in paths:
            try:
                d = self.billing(client, headers, path, realm=realm)
                break
            except BillingError as e:
                last = e
                if e.status not in (404, 405):
                    raise
        if d is None:
            raise last or BillingError("签到状态接口不可用")
        if not isinstance(d, dict):
            raise BillingError("签到状态格式异常")
        def flag(snake, camel):
            v = d.get(snake, d.get(camel))
            if v not in (True, False, 0, 1, "true", "false", "1", "0"):
                raise BillingError("签到状态缺少必要字段")
            return v in (True, 1, "true", "1")
        return {"active": flag("active", "active"), "checked": flag("today_checked_in", "todayCheckedIn")}

    def operate(self, aid, action, source="manual"):
        # 串行化按账号进行；把内层逻辑拆成 _operate 是为了让「锁外写日志」
        # 不会和自己抢同一把锁（threading.Lock 不可重入）。
        with self.operation_lock(aid):
            result = self._operate(aid, action)
        kind = ACTION_KINDS.get(action)
        if kind:
            self.log_task(aid, kind, result.get("ok"), result.get("message"), source,
                          credits=result.get("rewardCredit"))
        return result

    # ── 派猫猫旅行 / 保活：账号池给旅行模块提供的那三件适配 ──────────────
    def headers_for(self, aid):
        """该账号当前的鉴权头（过期先刷新），并带上它自己的出口线路。

        和 _operate 里同样的约束：刷新也是「以这个账号的身份出网」，必须走同一个
        出口；否则旅行走直连、对话走代理，上游看到的是两个来源共用一份凭证。
        """
        item, _ = self.snapshot(aid)
        manager = self.store.manager_for(aid, item)
        manager.proxy = egress.proxy_for(self.store, aid)
        return manager.get_headers()

    def refresh_account(self, aid):
        """强制刷一次凭据，供旅行模块在收到未授权时重试一次。

        返回 True **仅当确实换回了新凭据** ——返回数值型真假会让「刷了个空」
        被当成刷成功，然后拿同一个死 token 把请求重发一遍。
        """
        item, _ = self.snapshot(aid)
        manager = self.store.manager_for(aid, item)
        manager.proxy = egress.proxy_for(self.store, aid)
        try:
            with manager._lock:
                manager._refresh()
        except Exception:  # noqa: BLE001  凭据服务怎么坏都不该把调度打挂
            return False
        self.update(aid, token_refreshed=int(self.clock()), auth_invalid=False,
                    cooldown_until=0, last_error=None)
        return True

    def travel_state(self, aid):
        with self.store.lock:
            return dict((self.store.data.get("travel_states") or {}).get(aid) or {})

    def set_travel_state(self, aid, result):
        """把一次旅行结果落盘。没有值的字段跳过，别把已有信息盖成空。"""
        with self.store.lock:
            states = self.store.data.setdefault("travel_states", {})
            entry = dict(states.get(aid) or {})
            entry.update({k: v for k, v in result.items() if v is not None})
            entry["date"] = datetime.fromtimestamp(self.clock(), CN).strftime("%Y-%m-%d")
            entry["updated"] = int(self.clock())
            states[aid] = entry
            self.store.save()
        return entry

    def _travel(self, aid, action):
        """旅行动作统一入口：把旅行模块的结果折成 operate 的返回形状。"""
        try:
            headers = self.headers_for(aid)
        except Exception:  # noqa: BLE001
            return {"id": aid, "ok": False, "message": "读取账号凭据失败，已跳过"}
        # 国际版没有成长中心。拦在这里，别让调度对着必然失败的端点反复打——
        # 桌面端是靠 variant.supports_travel() 提前短路的，口径保持一致。
        # 判据用 X-Domain 而不是账号字段：域名的唯一权威就是凭据文件本身
        # （_operate 里判签到也是这么判的）。
        if "workbuddy.ai" in str(headers.get("X-Domain", "")).lower():
            return {"id": aid, "ok": False, "message": "国际版账号没有成长中心，已跳过"}

        runner = travel.TravelRunner(self, clock=self.clock)
        try:
            if action == "travel":
                result = runner.depart(aid)
            else:
                result = runner.sync(aid, self.travel_state(aid))
                if result.get("claimed") and result.get("rewardCredit"):
                    result["message"] = f"已领取旅行奖励 +{result['rewardCredit']}"
        except (httpx.HTTPError, OSError, RuntimeError, KeyError, ValueError) as e:
            # 不把原始响应或 bearer 凭据带出去。
            result = {"id": aid, "ok": False, "claimed": False, "skip": "error",
                      "state": "idle",
                      "message": "旅行操作失败：请检查登录凭据或网络"}
            # 存下的形状要与成功路径一致（含 state 与 claimed），否则界面在
            # 下一轮读到这条记录时会缺少判据：`result_in_flight` 看 ok/claimed，
            # 卡片看 state —— 少一个就显示成「状态未知」。
            # 上一次的 recordId / arriveAt 一并保留：那次行程可能还在途中，
            # 这次只是因为网络抖了一下没查到，不该把它忘掉。
            prior = self.travel_state(aid)
            stored = {k: prior.get(k) for k in ("recordId", "arriveAt", "locationName",
                                                "claimedAt", "rewardCredit")
                      if prior.get(k) not in (None, "", 0)}
            stored.update({"skip": "error", "ok": False, "claimed": False,
                           "state": "idle", "message": str(e)[:120]})
            self.set_travel_state(aid, stored)
            return result
        self.set_travel_state(aid, result)
        return result

    def _active(self, aid):
        """对话活跃上报：把 report 模块的结果折成 operate 的返回形状。

        与旅行不同，这里**不回写 uid**：body 里的 `userId` 直接取鉴权头上的
        `X-User-Id`，两边天然同源。从别处再取一次 uid 是多余的一次机会，
        取错就变成「200 但静默丢弃」——那种失败在日志里看不出任何异常。
        """
        try:
            headers = self.headers_for(aid)
        except Exception:  # noqa: BLE001
            return {"id": aid, "ok": False, "sent": 0, "message": "读取账号凭据失败，已跳过"}
        if "workbuddy.ai" in str(headers.get("X-Domain", "")).lower():
            # 国际版走另一个计费域，这里发的还是国内主机，必然失败。
            # 记成当天有效的终局跳过（而不是普通失败）：普通失败会按
            # 30 分钟节拍重试到当天结束，而这一类重试一万次也不会变好，
            # 只会往 500 条上限的流水里塞满同样的记录。
            self._note_active(aid, ok=False, skip="intl",
                              detail="当前仅支持国内账号，已跳过")
            return {"id": aid, "ok": False, "sent": 0, "skip": "intl",
                    "message": "当前仅支持国内账号，已跳过"}
        count = report.clamp_count(self.setting("active_reports", report.DEFAULT_REPORTS))
        streak = None
        streak_ok = None
        try:
            with self.client_for(aid) as client:
                result = report.report(client, headers, count, sleep=time.sleep)
                if result.get("ok"):
                    # 回读连登天数自检：上报 200 不等于生效，days=0 就是被静默丢弃了。
                    # 探针本身读不出来时 ok=False —— 那是「探不了」，不是「没生效」，
                    # 不能反过来把已经成功的上报判死（见 report.streak 的注释）。
                    check = report.streak(client, headers)
                    streak_ok = bool(check.get("ok"))
                    result["streak_ok"] = streak_ok
                    if streak_ok:
                        # 只有回读成功才有权写 streak。读失败时留 None，
                        # _note_active 会跳过这一项，不把已知天数抹成 0。
                        streak = check.get("days", 0)
                        result["streak"] = streak
                        if not streak:
                            result["message"] = "已上报，但连登天数仍为 0（可能被上游丢弃）"
                    else:
                        result["streak_unread"] = check.get("message") or ""
        except (httpx.HTTPError, OSError, RuntimeError, KeyError, ValueError) as e:
            # 异常口径与 _travel / _operate 对齐。捕窄了就会有漏网的类型：手动路径上
            # 它变成 HTTP 500，自动路径上它掀翻整个 tick —— 而两种表现都跟「上报」
            # 这件事本身没关系，排查时会往完全错误的方向找。
            # 不把原始响应或 bearer 凭据带出去（这里本来就只回固定文案；
            # 正常返回的失败信封那条路由 upstream.message_of 统一脱敏）。
            result = {"ok": False, "sent": 0, "count": count, "skip": "error",
                      "message": "活跃上报失败：请检查登录凭据或网络"}
            self._note_active(aid, ok=False, detail=str(e)[:120])
            return {"id": aid, **result}
        result["id"] = aid
        # 失败有两条来路：抛异常（上面 except 分支），以及正常返回了一个失败信封
        # （网络通、上游拒了）。后者不走 except，早先就把失败原因丢了——界面上只看到
        # 「失败」两个字，无从判断该不该重试。两条路必须都落到同一个记账点。
        # `effective` = 有正面证据证明事件真的生效了，也就是回读成功且天数 > 0。
        # 两种「没能证明生效」的形态（探针坏了 / 探到 0）都不算数，但它们留下的痕迹不同，
        # 所以别在这里把 streak_ok 揉成一个布尔——_note_active 还要用它区分措辞。
        self._note_active(aid, ok=bool(result.get("ok")), streak=streak,
                          streak_ok=streak_ok,
                          detail=None if result.get("ok") else result.get("message"))
        return result

    def _note_active(self, aid, ok, streak=None, streak_ok=None, detail=None, skip=None):
        """记一次活跃上报的尝试。**「报上去了」与「当天结束了」是两件事。**

        三档落点，判据各不相同：

          · `ok` 为假          → 失败。记 `active_error`、只记尝试时间戳，
                                  按 ACTIVE_RETRY_SECONDS 重试；
          · `ok` 为真 + `streak_ok` 为真且天数 > 0 → 事件确实生效了。写
                                  `active_date` = 当天，当天不再重做（这就是
                                  「每号每天一轮」）；
          · `ok` 为真但没能证明生效     → **上报 200 但被静默丢弃**
                                  （回读成功而 days 仍是 0，或回读根本读不出来）。
                                  这条**不写** `active_date`：把它当成当天已完成，
                                  等于「检测出了问题，然后把自愈的路关掉」——
                                  剩下的半天里一条都不再试，用户看到的是永远
                                  点不亮的连登和一个查不出原因的 0。

        `streak` 只在**回读成功**时才传进来。回读失败时它是 None，而我们**不写**
        active_streak——把它写成 0 会把上一次读到真实天数（比如 9）抹掉，用户看到
        连登天数突然归零，而事件其实好好地报上去了。读不到 ≠ 是 0，这两个必须分开。

        `skip` 是**当天有效的终局跳过**（例如国际版账号）。它单独记一个带日期的键，
        因为「它今天不用再试」和「它今天成功了」在界面上是两件事。
        """
        today = datetime.fromtimestamp(self.clock(), CN).strftime("%Y-%m-%d")
        fields = {"auto_active_attempt": int(self.clock())}
        # 只有「回读成功且天数 > 0」才算拿到了生效的正面证据。
        # streak_ok 为 None 表示这一轮压根没走到回读（上报就失败了）。
        verified = streak_ok is True and bool(streak)
        if ok and verified:
            fields["active_date"] = today
            fields["active_streak"] = streak
            # 成功就把上一次的失败原因清掉。留着它会让账号卡片上永远挂着一条
            # 「已经解决了的」报错——那种陈旧状态比没有状态更误导人。
            fields["active_error"] = None
        elif skip in ACTIVE_TERMINAL_SKIPS:
            # 终局跳过按天记：跨天自动失效，不需要清理逻辑。
            fields["active_skip"] = skip
            fields["active_skip_date"] = today
            fields["active_error"] = detail or None
        elif ok:
            # 报到服务端了、但没能证明生效。两种形态措辞要分开——
            # 「探到 0」意思是我们确实看见事件没生效；「读不到」只是探针坏了，
            # 事件很可能成了。把两者写成同一句话会让人以为确定没生效。
            if streak_ok is True:
                fields["active_error"] = "已上报，但连登天数仍为 0（可能被上游丢弃）"
            else:
                fields["active_error"] = "已上报，但连登状态未能确认"
        if detail and not (skip in ACTIVE_TERMINAL_SKIPS):
            fields["active_error"] = detail
        self.update(aid, **fields)

    def setting(self, key, fallback=None):
        with self.store.lock:
            return self.store.data["pool"].get(key, fallback)

    def upstream_cooldowns(self, *, force: bool = False) -> dict:
        """读一次上游 workbuddy2api 的 `/status`，返回 `{uid: 冷却 view}`。

        为什么要缓存：`rows()` 是面板刷新路径，几秒就调一次；而上游
        `/status` 要跨网络。每刷一次都去读，既慢又给对方添压力。缓存
        `UPSTREAM_TTL` 秒。

        为什么失败要静默：这个数据源是「锦上添花」——我们自己的
        `cooldown_until` 本来就能用。上游没跑 / 超时 / 返回垃圾，
        都不该让整个账号列表刷不出来。失败时把错误记在 `_upstream_error`
        里（界面可以说明「上游读不到」，但列表照常出）。
        """
        configured = str(self.setting("wb2api_base", "") or "").strip()
        if not configured:
            # 没配就是没这回事，连缓存都不必维护。
            # 错误也必须一起清 —— 否则用户把地址清空之后，
            # 界面还会挂着一条上一次遗留的「上游读不到」，
            # 那是照着已经不存在的配置在报警。
            self._upstream_cache = ({}, None, 0.0)
            self._upstream_error = None
            return {}
        now = self.clock()
        cached, error, at = getattr(self, "_upstream_cache", ({}, None, 0.0))
        if not force and at and now - at < UPSTREAM_TTL:
            self._upstream_error = error
            return cached
        try:
            raw = wb2api.fetch_status(configured, str(self.setting("wb2api_key", "") or ""))
            cached = {uid: wb2api.view(info, now=now) for uid, info in raw.items()}
            error = None
        except wb2api.Wb2ApiError as exc:
            # 读不到就沿用上一次成功的结果——冷却是个慢慢过期的东西，
            # 上一次的读数比「什么都没有」更接近真相。但错误必须记下来，
            # 否则界面会把陈旧数据当成实时数据展示。
            error = str(exc)
        self._upstream_cache = (cached, error, now)
        self._upstream_error = error
        return cached

    def upstream_error(self) -> str:
        """最近一次读上游 `/status` 的失败原因（空串 = 没出错）。

        为什么要暴露它：`upstream_cooldowns()` 失败时会静默沿用上次缓存，
        设计上是对的（冷却数据是锦上添花，不该拖垮账号列表）。但「沿用上次
        结果」和「刚刚读到的结果」在界面上长得一模一样 —— 用户看到一份可能已经
        过期的冷却台账，却以为它是实时的。

        把它透出去之后，界面就能把「上游读不到、冷却状态未知」和「上游说没冷却」
        区分开。**这不是给数据加语义，是把已经记下来的事实读出来** ——
        这个属性在 `upstream_cooldowns()` 里本来就一直被写。

        为什么不直接读 `self._upstream_error`：属性是懒初始化的（见 __init__），
        而且 `rows()` 可能在任何一次 `upstream_cooldowns()` 之前被调用 ——
        用 getattr 兜底，读方永远拿得到字符串。
        """
        return str(getattr(self, "_upstream_error", "") or "")


    def _operate(self, aid, action):
        item, previous = self.snapshot(aid)
        if not item["enabled"]:
            return {"id": aid, "ok": False, "message": "账号已暂停，未执行操作"}
        if action == "active":
            return self._active(aid)
        if action in ("travel", "travel-claim"):
            # 旅行自己经 headers_for 取凭据（出口线路与刷新口径都在那里），
            # 这里不再多取一次 manager。
            return self._travel(aid, action)
        manager = self.store.manager_for(aid, item)
        # token 刷新也是「以这个账号的身份出网」，必须和它平时的出口一致：
        # 否则刷新走直连、对话走代理，上游看到的就是两个来源在共用同一个凭证。
        manager.proxy = egress.proxy_for(self.store, aid)
        try:
            if action == "refresh":
                with manager._lock:
                    manager._refresh()
                self.update(aid, token_refreshed=int(self.clock()), auth_invalid=False, cooldown_until=0, last_error=None)
                return {"id": aid, "ok": True, "message": "登录凭据已刷新"}
            headers = manager.get_headers()
            realm = realm_mod.realm_of(item)
            today = datetime.fromtimestamp(self.clock(), CN).strftime("%Y-%m-%d")
            with self.client_for(aid) as client:
                message = "积分状态已更新"
                checkin_error = None
                # 国际版没有签到体系：**先判断再决定发不发**。
                # 以前这里是对所有账号都发 daily-checkin，国际版拿回业务错误码，
                # 被记成一次失败 → consecutive_fails 累加 → 误报「账号连续失败」。
                # 现在直接跳过，且 ok=True —— 「该版本没有这个功能」不是失败。
                if not realm_mod.supports_checkin(realm):
                    if action == "checkin":
                        message = realm_mod.unsupported_message("checkin", realm)
                else:
                    try:
                        ci = self.checkin_status(client, headers, realm)
                        if ci["checked"]:
                            self.update(aid, checkin_date=today)
                        if action == "checkin":
                            if ci["checked"]:
                                message = "今日已签到，无需重复签到"
                            elif not ci["active"]:
                                message = "当前没有可参与的签到活动"
                            else:
                                self.billing(client, headers, "daily-checkin", realm=realm)
                                ci = self.checkin_status(client, headers, realm)
                                if not ci["checked"]:
                                    raise BillingError("签到已提交，但上游尚未确认；请刷新状态")
                                self.update(aid, checkin_date=today)
                                message = "签到成功"
                    except (BillingError, httpx.HTTPError):
                        if action == "checkin":
                            raise
                        checkin_error = "签到状态暂时无法查询"
                data = self.credits(client, headers, realm)
                # A successful balance lookup is proof of current authentication.
                self.update(aid, **data, credits_updated=int(self.clock()), auth_invalid=False, last_error=checkin_error)
                # 不限量账号的 remaining 是 None（不是 0）：`None > 0` 会抛 TypeError，
                # 所以必须先判 None。语义上「不限量」永远不会因额度耗尽进冷却。
                remaining = data.get("remaining")
                if remaining is not None and remaining > 0 and action == "checkin":
                    self.update(aid, cooldown_until=0)
                return {"id": aid, "ok": True, "message": message, "remaining": remaining}
        except BillingError as e:
            self.update(aid, last_error=str(e))
            if e.status in (401, 403):
                self.update(aid, cooldown_until=self.clock()+300)
            return {"id": aid, "ok": False, "message": str(e)}
        except (httpx.HTTPError, OSError, ValueError, RuntimeError, KeyError):
            # Do not expose raw refresh responses or bearer credentials.
            message = "操作失败：请检查登录凭据或网络，必要时重新授权"
            self.update(aid, last_error=message)
            return {"id": aid, "ok": False, "message": message}

    async def batch(self, action):
        if self.jobs.locked():
            raise HTTPException(409, "已有批量任务进行中，请稍后刷新")
        async with self.jobs:
            with self.store.lock:
                ids = [aid for aid, item in self.store.data["accounts"].items() if item["enabled"]]
            semaphore = asyncio.Semaphore(3)
            async def run(aid):
                async with semaphore:
                    try:
                        return await asyncio.to_thread(self.operate, aid, action, "batch")
                    except HTTPException:
                        return {"id": aid, "ok": False, "message": "账号已移除"}
            return {"results": await asyncio.gather(*(run(aid) for aid in ids))}

    def travel_depart_due(self, cfg, now_hm, today):
        """这一轮该派旅行的账号。

        三种「今天不用再派」：已有行程（交给领奖对账）、当日名额已用完
        （官网 idle + daily_limit_reached，即「累了，明天再来吧」）、以及
        不可重试的失败。只有可重试失败才会按 30 分钟一轮继续试。
        """
        # 时间先归一化：字符串比较对 `"9:00"` 这种非补零形态会变成字典序，
        # 方向是「永远不开闸」——整个功能当天一个账号都不派，且完全静默。
        if now_hm < _clock_hm(cfg.get("travel_time"), "08:30"):
            return []
        with self.store.lock:
            accounts = dict(self.store.data["accounts"])
            states = dict(self.store.data.get("travel_states") or {})
        due = []
        for aid, item in accounts.items():
            if not item["enabled"]:
                continue
            state = states.get(aid) or {}
            same_day = state.get("date") == today
            if same_day:
                if travel.result_in_flight(state):
                    continue
                if not travel.is_retryable_skip(state.get("skip")):
                    continue
                if int(state.get("updated") or 0) > self.clock() - TRAVEL_RETRY_SECONDS:
                    continue
            due.append(aid)
        return due

    def travel_claim_due(self):
        """这一轮该回查 / 领奖的账号：有行程、已到点、且距上次对账超过 15 分钟。

        没到点的不回查——本地缓存里有 arrive_at，够判断了，没必要每个 tick
        都拿同一个问题去问上游。
        """
        with self.store.lock:
            accounts = dict(self.store.data["accounts"])
            states = dict(self.store.data.get("travel_states") or {})
        due = []
        for aid, item in accounts.items():
            if not item["enabled"]:
                continue
            state = states.get(aid) or {}
            if not travel.result_in_flight(state):
                continue
            if not travel.in_flight_due(state, self.clock()):
                continue
            if int(state.get("updated") or 0) > self.clock() - TRAVEL_CLAIM_SECONDS:
                continue
            due.append(aid)
        return due

    def active_due(self, cfg, now_hm, today):
        """这一轮该做活跃上报的账号。

        判据全在**本地**，一次上游请求都不发：
          · 没开 auto_active 就不管；
          · 没到 active_time 不报（和派旅行同一个窗口口径：时间到了才开闸）。
            时间先过 `_clock_hm` 归一化——不归一化的话，配置里一个
            `"9:00"` 就让整个功能当天一个账号都不派，且完全静默；
          · 今天已经**成功**报过就不重做——`active_date == today`。它按天幂等，
            重复报不会多拿积分，只会多打几次上游；
          · 命中了当天有效的终局跳过（`active_skip`，例如国际版账号）也不重做；
          · 其余失败按 ACTIVE_RETRY_SECONDS 退避，别每个 tick 都对同一个必然
            失败的原因（比如凭据失效）打一次。

        「成功」必须包含「事件真的生效」：只写了 `active_date` 不代表当天就
        结束了——「上报 200 但被静默丢弃」的形态在 `_note_active` 里被刻意排除在
        `active_date` 之外，就是为了让它还能按节拍重试。
        """
        if not cfg.get("auto_active"):
            return []
        if now_hm < _clock_hm(cfg.get("active_time")):
            return []
        with self.store.lock:
            accounts = dict(self.store.data["accounts"])
            status = {aid: dict(self.store.data["account_status"].get(aid) or {})
                      for aid in accounts}
        due = []
        for aid, item in accounts.items():
            if not item["enabled"]:
                continue
            state = status.get(aid) or {}
            if state.get("active_date") == today:
                continue
            if state.get("active_skip_date") == today \
                    and state.get("active_skip") in ACTIVE_TERMINAL_SKIPS:
                continue
            if _stamp(state.get("auto_active_attempt")) > self.clock() - ACTIVE_RETRY_SECONDS:
                continue
            due.append(aid)
        return due

    def keepalive_due(self, hours):
        """token 剩余寿命不足 `hours` 小时的账号。

        没有 refresh token 的账号直接跳过：刷了必然失败，还会在流水里刷出一串
        无意义的报错。到期时间是 0（凭据里没写）时按「已过期」处理——那时候
        它本来就得靠刷新续命。
        """
        horizon = self.clock() * 1000 + hours * 3600_000
        with self.store.lock:
            checked = {aid: int((self.store.data["account_status"].get(aid) or {}).get("keepalive_checked") or 0)
                       for aid in self.store.data["accounts"]}
        try:
            rows = self.store.account_rows()
        except Exception:  # noqa: BLE001  账号库读不出来不该把整轮 tick 打挂
            return []
        due = []
        for row in rows:
            if not row.get("enabled") or row.get("status") != "ready":
                continue
            if not row.get("refresh_available"):
                continue
            if checked.get(row["id"], 0) > self.clock() - KEEPALIVE_CHECK_SECONDS:
                continue
            expires = row.get("expires_at") or 0
            if expires and expires > horizon:
                continue
            due.append(row["id"])
        return due

    async def tick(self):
        now = datetime.fromtimestamp(self.clock(), CN)
        today = now.strftime("%Y-%m-%d")
        with self.store.lock:
            cfg = dict(self.store.data["pool"])
            due = [aid for aid, item in self.store.data["accounts"].items() if item["enabled"] and self.store.data["account_status"].get(aid, {}).get("checkin_date") != today and self.store.data["account_status"].get(aid, {}).get("auto_attempt", 0) < self.clock()-1800]
        if cfg["auto_checkin"] and now.strftime("%H:%M") >= cfg["checkin_time"]:
            for aid in due:
                self.update(aid, auto_attempt=int(self.clock()))
                try:
                    await asyncio.to_thread(self.operate, aid, "checkin", "auto")
                except HTTPException:
                    pass
        if cfg["auto_travel"]:
            # 一批一批来：首次打开开关时全部账号同时到点，一次 tick 里打出一串
            # 同源请求既不好看也不安全。被处理过的账号 30 分钟内不再入选，
            # 所以下一批自然是剩下的，不会饿死后面的账号。
            for aid in self.travel_depart_due(cfg, now.strftime("%H:%M"), today)[:TRAVEL_BATCH_PER_TICK]:
                try:
                    await asyncio.to_thread(self.operate, aid, "travel", "auto")
                except HTTPException:
                    pass
        # 领奖对账不受 auto_travel 约束：关掉自动派发不该让已经派出去的行程
        # 白跑一趟——那是账号自己攒下的积分。
        for aid in self.travel_claim_due()[:TRAVEL_BATCH_PER_TICK]:
            try:
                await asyncio.to_thread(self.operate, aid, "travel-claim", "auto")
            except HTTPException:
                pass
        if cfg["auto_active"]:
            # 活跃上报：同样一批一批来（见旅行的同一处理）。被处理过的账号在
            # ACTIVE_RETRY_SECONDS 内不再入选，所以剩下的账号下一批自然轮上。
            # 每号每天只成功一轮：成功即写 active_date，当天不再入选。
            for aid in self.active_due(cfg, now.strftime("%H:%M"), today)[:TRAVEL_BATCH_PER_TICK]:
                # 先记尝试时间再动手：上报里串了「逐条发 + 回读连登」多次往返，
                # 中途挂住也不会让下一个 tick 立刻重来一次。
                self.update(aid, auto_active_attempt=int(self.clock()))
                try:
                    await asyncio.to_thread(self.operate, aid, "active", "auto")
                except HTTPException:
                    pass
        if cfg["auto_keepalive"] and cfg["keepalive_hours"] > 0:
            for aid in self.keepalive_due(cfg["keepalive_hours"])[:TRAVEL_BATCH_PER_TICK]:
                # 先记检查时间再动手：凭据服务挂住时也不会每个 tick 重来一次。
                self.update(aid, keepalive_checked=int(self.clock()))
                try:
                    await asyncio.to_thread(self.operate, aid, "refresh", "auto")
                except HTTPException:
                    pass
        if self.clock() - self.last_sync > 300 and not self.jobs.locked():
            await self.batch("status")
            self.last_sync = self.clock()
        # 用量聚合的兜底落盘：每分钟最多一次，别让分桶只活在内存里。
        #
        # 失败必须留痕。 这里是 usage_stats 唯一的周期性落盘点：
        # request_log 是内存 deque，分桶也只在内存里。state.json 要是长期写不进去
        # （只读挂载 / 磁盘满 / 权限错），面板照样显示实时流量，
        # 但重启之后什么都留不下 —— 而日志里一条线索都没有，根本无从查起。
        #
        # 仍然不往上抛：异常会打断整个 tick 循环，而 tick 还要干同步账号状态、
        # 刷新额度这些更不能停的事。所以只把失败报到 stderr，然后继续跑。
        try:
            self.flush_usage()
        except Exception as exc:  # noqa: BLE001
            print(f"[reverse-proxy] 用量聚合落盘失败：{exc}", file=sys.stderr)

        # 告警扫描：放在最后，且自己吞掉全部异常 —— 发信要 15 秒超时，
        # 绝不能因为它打断上面那些更不能停的事。
        try:
            self.scan_alerts()
        except Exception as exc:  # noqa: BLE001
            print(f"[reverse-proxy] 告警扫描失败：{exc}", file=sys.stderr)

    def scan_alerts(self):
        """扫描账号池，把**新出现**的告警发给管理员。

        去重靠状态跃迁：告警指纹存进 `state.alerts.fired`，同一批只报一次；
        恢复（指纹变了）之后再告急才会再报。另外有 6 小时重发窗口兜底，
        防止状态在阈值边缘抖动导致反复发信。
        """
        cfg = alerts.load(self.store)
        if not cfg.get("enabled"):
            return
        if not cfg.get("to") or not cfg.get("host"):
            return
        if alerts.in_quiet_hours(cfg):
            return

        now = datetime.fromtimestamp(self.clock(), CN)
        with self.store.lock:
            fired = dict((self.store.data.get("alerts") or {}).get("fired") or {})
            last_sent = float((self.store.data.get("alerts") or {}).get("last_sent") or 0)

        rows = self.rows(self.store.account_rows())
        # 密钥级和池级告警需要额外两份数据。
        # 都取「拿不到就传 None」的姿态：某个来源出错只该让对应的那类告警
        # 不参与，不该让整轮扫描挂掉 —— 告警系统自己崩了，等于所有告警都没了。
        try:
            with self.store.lock:
                raw_keys = dict((self.store.data.get("keys") or {}))
            key_list = [keysvc.public_key(kid, item)
                        for kid, item in raw_keys.items() if isinstance(item, dict)]
        except Exception:  # noqa: BLE001
            key_list = None
        try:
            # 「密钥连续被拒」只看最近的：30 天前的一串 401 不该让今天报警。
            recent_logs = self.request_logs(200)
        except Exception:  # noqa: BLE001
            recent_logs = None
        fresh = alerts.detect(rows, cfg, fired, now, keys=key_list, logs=recent_logs)
        if not fresh:
            return
        if self.clock() - last_sent < alerts.REPEAT_WINDOW_SEC:
            return

        def record_error(message):
            with self.store.lock:
                bucket = self.store.data.setdefault("alerts", {})
                bucket["last_error"] = message
                bucket["last_error_at"] = int(self.clock())
                self.store.save()

        alerts.send_alerts_async(cfg, fresh, on_error=record_error)

        with self.store.lock:
            bucket = self.store.data.setdefault("alerts", {})
            fired_now = dict(bucket.get("fired") or {})
            for alert in fresh:
                fired_now[alert["key"]] = alert["fingerprint"]
            bucket["fired"] = fired_now
            bucket["last_sent"] = int(self.clock())
            bucket["last_kinds"] = [a["kind"] for a in fresh]
            self.store.save()


def request_affinity(headers, body):
    """Persist only a hash of caller/model/session identity, never raw prompts or keys."""
    if not isinstance(body, dict):
        return None
    identity = None
    for name in (b"x-session-id", b"session_id", b"x-conversation-id"):
        if headers.get(name):
            identity = [name.decode(), headers[name].decode(errors="replace")]
            break
    if identity is None:
        for name in ("prompt_cache_key", "conversation_id", "session_id"):
            if body.get(name):
                identity = [name, body[name]]
                break
    if identity is None:
        messages = body.get("messages", body.get("input", []))
        if isinstance(messages, str) and messages:
            identity = ["first_user", messages]
        elif isinstance(messages, list):
            for message in messages:
                if isinstance(message, dict) and message.get("role") == "user":
                    identity = ["first_user", message.get("content", "")]
                    break
    if identity is None:
        return None
    caller = headers.get(b"authorization") or headers.get(b"x-api-key", b"")
    value = [caller.decode(errors="replace"), body.get("model", "auto"), identity]
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _usage_of(obj) -> tuple[int, float]:
    """从响应对象里抽取 (tokens, credit)。找不到返回 (0, 0.0)。

    兼容三种形态：OpenAI（usage.total_tokens）、Anthropic（usage.input_tokens +
    output_tokens）、以及包裹在 message / response 下的 usage。
    """
    usage = None
    if isinstance(obj, dict):
        usage = obj.get("usage")
        if usage is None and isinstance(obj.get("message"), dict):
            usage = obj["message"].get("usage")
        if usage is None and isinstance(obj.get("response"), dict):
            usage = obj["response"].get("usage")
    if not isinstance(usage, dict):
        return 0, 0.0
    tokens = usage.get("total_tokens")
    if tokens is None:
        total = 0
        for k in ("input_tokens", "output_tokens"):
            v = usage.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                total += int(v)
        tokens = total or usage.get("completion_tokens", 0)
    try:
        tokens = int(tokens or 0)
    except (TypeError, ValueError):
        tokens = 0
    credit = usage.get("credit")
    try:
        credit = float(credit) if credit is not None else 0.0
    except (TypeError, ValueError):
        credit = 0.0
    return max(tokens, 0), credit


def _cached_of(obj) -> int:
    """抽取「命中缓存的输入 token 数」。拿不到返回 0。

    各家字段名不同，都见一遍：
      OpenAI      usage.prompt_tokens_details.cached_tokens
      Anthropic   usage.cache_read_input_tokens
      部分网关     usage.cached_tokens
    命中缓存能让 prompt cache 生效、账单显著变便宜，所以值得单列出来。
    """
    usage = None
    if isinstance(obj, dict):
        usage = obj.get("usage")
        if usage is None and isinstance(obj.get("message"), dict):
            usage = obj["message"].get("usage")
        if usage is None and isinstance(obj.get("response"), dict):
            usage = obj["response"].get("usage")
    if not isinstance(usage, dict):
        return 0
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        value = details.get("cached_tokens")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0, int(value))
    for key in ("cache_read_input_tokens", "cached_tokens"):
        value = usage.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0, int(value))
    return 0


class PoolMiddleware:
    def __init__(self, app, pool):
        self.app, self.pool = app, pool

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in {"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/messages/count_tokens"}:
            return await self.app(scope, receive, send)
        started = time.monotonic()
        headers = dict(scope.get("headers", []))
        key = None
        ip = None
        model = None
        upstream_model = None
        aid = None
        # 已占住名额的账号 id。`None` = 什么都没占（select 就失败了），
        # 此时 finally 里的 release 不该被触发。
        # 必须在 try 之前初始化：select() 可能先抛 HTTPException 直接跳进
        # except，那时 try 块里的赋值一条都没执行。
        granted = None
        try:
            key = self.pool.store.check_api(headers.get(b"authorization", b"").decode(), headers.get(b"x-api-key", b"").decode())
            raw = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                raw.extend(message.get("body", b""))
                if len(raw) > 32 * 1024 * 1024:
                    raise HTTPException(413, "请求体超过 32 MiB")
                if not message.get("more_body", False):
                    break
            raw = bytes(raw)
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                body = {}
            if isinstance(body, dict) and isinstance(body.get("model"), str):
                model = body["model"]
            # 模型别名映射：把下游在用的名字映到真实模型。判版本归属（realm）用映射后的名字，
            # 判模型白名单仍用客户端给的名字——用户配的白名单里写的就是他平时用的那个名字。
            upstream_model = keysvc.resolve_model_alias(self.pool.store, model) if model else None
            if upstream_model and upstream_model != model and isinstance(body, dict):
                body["model"] = upstream_model
                raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
                headers[b"content-length"] = str(len(raw)).encode()
                scope = {**scope, "headers": list(headers.items())}
            # 密钥的 IP / 模型白名单与版本归属：必须在拿到 model 后校验。
            if key:
                ip = client_ip_from_scope(scope)
                keysvc.validate(key, ip, model, mapped_model=upstream_model)
            affinity_key = request_affinity(headers, body)
            original_receive = receive
            delivered = False
            async def replay_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": raw, "more_body": False}
                return await original_receive()
            receive = replay_receive
            aid, manager = self.pool.select(affinity_key, key=key)
            # 占一个在途名额。顺序是「换号 → 排队 → 兜底放行」：
            #
            # 1. 先换一个号试试。多数情况下换号就能占到，不必让用户等。
            # 2. 换号也不行，说明卡的是**全池总量闸门**（换号不会改变总数），
            #    那就短暂让出事件循环再重试几次。把闸门变成硬拒绝会让
            #    「上限 8、同时来了 20 个」时后 12 个直接失败——用户配这一项
            #    的本意是「排一下队」，不是「直接拒绝」。
            # 3. 排队也超时，跟着 select 的兜底走（挑欠账最少的号），
            #    宁可超一点也不要报「暂无可用账号」——那会让人以为服务挂了。
            if not self.pool.acquire(aid):
                aid, manager = self.pool.select(affinity_key, key=key)
                if not self.pool.acquire(aid):
                    for _ in range(GATE_RETRIES):
                        await asyncio.sleep(GATE_RETRY_DELAY)
                        if self.pool.acquire(aid, ignore_gate=False):
                            break
                    else:
                        # 兜底放行：只占账号级名额，不再计全局闸门。
                        # 注意这里**必须**成功，否则后面的 release 会多减一次。
                        self.pool.acquire(aid, ignore_gate=True)
            granted = aid

            def bind_egress(account_id, cred):
                """把选中的账号绑到它那条出口线路上（无线路 = 直连 = None）。"""
                url = egress.proxy_for(self.pool.store, account_id)
                cred.proxy = url
                return url

            egress_url = bind_egress(aid, manager)
            # Refresh before entering a stream; retry another eligible account only
            # if credential preparation fails, never replay a partially emitted response.
            try:
                await asyncio.to_thread(manager.get_headers)
            except Exception:
                # 换号：把刚才占的名额还回去，否则那次失败的占用会永久计在这个号上。
                if granted is not None:
                    self.pool.release(granted)
                self.pool.update(aid, cooldown_until=self.pool.clock()+300, last_error="凭据暂不可用，已冷却 5 分钟")
                aid, manager = self.pool.select(affinity_key, key=key)
                self.pool.acquire(aid)
                granted = aid
                egress_url = bind_egress(aid, manager)
                await asyncio.to_thread(manager.get_headers)
        except HTTPException as e:
            # 走到这里说明名额还没占到（select 就失败了），无需归还。
            # 503 只可能来自 select()——即「一个可用账号都没有」。把它和
            # 「密钥被规则挡下」区分开，日志页才能一眼看出该去补账号还是改密钥。
            self.pool.log_request(aid, model, e.status_code, False, 0, 0,
                                  (time.monotonic()-started)*1000,
                                  "no_account" if e.status_code == 503 else "rejected")
            return await JSONResponse({"detail": e.detail}, e.status_code)(scope, receive, send)
        except Exception:
            self.pool.log_request(aid, model, 503, False, 0, 0,
                                  (time.monotonic()-started)*1000, "no_account")
            return await JSONResponse({"detail": "账号凭据暂不可用，请刷新凭据或重新授权"}, 503)(scope, receive, send)
        token = REQUEST_CREDENTIAL.set(manager)
        egress_token = egress.REQUEST_EGRESS.set(egress_url)
        status = 200
        buffer = b""
        tokens_used = 0
        credit_used = 0.0
        cached_used = 0
        # 已向下游发过多少字节。这是「还能不能重试」的唯一判据。
        sent_bytes = 0
        with self.pool.store.lock:
            mirror_cfg = dict(self.pool.store.data.get("pool") or {})
        attempt = 0
        mirror_used = 0
        # 首个非空响应分片到达的耗时（毫秒）。流式下就是"首字延迟"的近似值：
        # 上游要先建连、鉴权、跑完 prefill 才会吐出第一个 chunk，慢在这一段最容易被误判成"卡住"。
        first_token_ms = 0
        async def observe(message):
            nonlocal status, buffer, tokens_used, credit_used, cached_used, first_token_ms
            if message["type"] == "http.response.start":
                status = message["status"]
            if message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                if chunk and not first_token_ms:
                    first_token_ms = max(1, int((time.monotonic() - started) * 1000))
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.startswith(b"data:"):
                        try:
                            obj = json.loads(line[5:])
                            err = obj.get("error") or (obj.get("response") or {}).get("error") or {}
                            code = err.get("code") if isinstance(err, dict) else None
                            if isinstance(code, str) and code.isdigit():
                                code = int(code)
                            if code in (401, 402, 403, 429):
                                status = code
                            t, c = _usage_of(obj)
                            if t:
                                tokens_used = t
                            if c:
                                credit_used += c
                            cached = _cached_of(obj)
                            if cached:
                                cached_used = cached
                        except (ValueError, AttributeError):
                            pass
                if not message.get("more_body", False):
                    # 非流式响应：整体 JSON 在此解析用量（流式已在上面按行处理）。
                    if buffer and not buffer.startswith(b"data:"):
                        try:
                            obj = json.loads(buffer)
                            t, c = _usage_of(obj)
                            if t:
                                tokens_used = t
                            if c:
                                credit_used += c
                            cached = _cached_of(obj)
                            if cached:
                                cached_used = cached
                        except (ValueError, AttributeError):
                            pass
                if len(buffer) > 65536:
                    buffer = b""
            if message["type"] == "http.response.body":
                nonlocal sent_bytes
                sent_bytes += len(message.get("body", b"") or b"")
            await send(message)
        while True:
            # 镜像加速：上游 5xx 或连接层失败时，先重试再判死。
            # 默认关闭（pool.retry_enabled 为 False），所以这一段对存量部署是空转。
            try:
                await self.app(scope, receive, observe)
            except Exception:
                # 连接层失败（超时 / 重置 / DNS）。上游什么都没答，但 status 还停在
                # 200，必须显式改掉，否则下面会把它当成成功。
                status = 599
            if 200 <= status < 300:
                break
            # 已经向下游吐过字节就不能重试：会在流中间插进另一份完整的回答。
            if sent_bytes:
                break
            # 连接层失败的 status 传 None，让 should_retry 认成"值得重试"。
            signal = None if status == 599 else status
            if not mirror.should_retry(signal, attempt, mirror_cfg):
                break
            await asyncio.sleep(mirror.delay_ms(attempt, mirror_cfg) / 1000.0)
            attempt += 1
            mirror_used = attempt
            # 换一个号再试：同一个号刚 5xx 过一次，立刻原样重放大概率还是 5xx。
            # 名额要还回去再占新的，否则那个号的在途计数永远少减一次。
            try:
                if granted is not None:
                    self.pool.release(granted)
                    granted = None
                aid, manager = self.pool.select(affinity_key, key=key)
                self.pool.acquire(aid)
                granted = aid
                REQUEST_CREDENTIAL.set(manager)
            except HTTPException:
                granted = None
                break
            status = 200
            buffer = b""
            tokens_used = 0
            credit_used = 0.0
            cached_used = 0
            first_token_ms = 0
        try:
            pass  # 主体已在 while 循环里调完；这里只为让 finally 的归属保持直白
        finally:
            REQUEST_CREDENTIAL.reset(token)
            egress.REQUEST_EGRESS.reset(egress_token)
            # 必须先还名额再记状态：`record` 会更新 last_request，
            # 而并发上限的判断依赖 inflight 已经归位。
            if granted is not None:
                self.pool.release(granted)
            self.pool.record(aid, status)
            self.pool.log_request(aid, model, status, 200 <= status < 300,
                                  tokens_used, credit_used, (time.monotonic()-started)*1000,
                                  "success" if 200 <= status < 300 else "upstream_error",
                                  "test" if key is None else "api",
                                  first_token_ms=first_token_ms,
                                  cached_tokens=cached_used,
                                  upstream_model=upstream_model,
                                  key_id=(key or {}).get("id"),
                                  key_name=(key or {}).get("name"),
                                  key_hint=(key or {}).get("hint"))
            if key and key.get("id"):
                keysvc.touch_key(self.pool.store, key["id"], ip, tokens_used, credit_used)
