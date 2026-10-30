# -*- coding: utf-8 -*-
"""上游渠道校验头（11128 "Illegal API invocation from an unapproved channel"）。

被提升检测等级的账号，上游会要求两样东西同时到位，否则一律
`400 {"code":11128,...}`：

  1. `User-Agent` 不能是第三方反代的标识（以前是 `codebuddy2openai/2.0`），
     也不能为空；
  2. `X-Conversation-ID` / `X-Conversation-Request-ID` / `X-Conversation-Message-ID`
     三枚会话头一个都不能少。

这些测试盯的是「三枚头一定在、并且同一条对话里稳定」这两件事——
它们恰好是最容易在重构里悄悄丢掉的：丢了不报错，只是换个账号就不能用了。
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import converter  # noqa: E402

CHANNEL_KEYS = (
    "X-Conversation-ID",
    "X-Conversation-Request-ID",
    "X-Conversation-Message-ID",
)


class UserAgentTests(unittest.TestCase):
    def test_user_agent_is_official_shaped(self):
        self.assertNotIn("codebuddy2openai", converter.USER_AGENT)
        self.assertTrue(converter.USER_AGENT.startswith("WorkBuddy/"))
        # 上游把空 UA 也当成「不是官方客户端」，所以至少要两段
        self.assertGreaterEqual(len(converter.USER_AGENT.split()), 2)

    def test_global_realm_uses_workbuddy_ai_segment(self):
        """国际版官方 UA 的第二段是 `WorkBuddy AI`（带空格），抄错就自曝。"""
        cn = converter._official_user_agent("6.0.0", "cn")
        glob = converter._official_user_agent("6.0.0", "global")
        self.assertIn("WorkBuddy/6.0.0 WorkBuddy/6.0.0 ", cn)
        self.assertIn("WorkBuddy/6.0.0 WorkBuddy AI/6.0.0 ", glob)

    def test_realm_can_come_from_domain(self):
        self.assertEqual(converter._realm_from({"domain": "www.workbuddy.ai"}), "global")
        self.assertEqual(converter._realm_from({"domain": "https://www.workbuddy.ai/x"}), "global")
        self.assertEqual(converter._realm_from({"domain": "www.codebuddy.cn"}), "cn")
        # 后缀对齐：伪域不能命中
        self.assertEqual(converter._realm_from({"domain": "workbuddy.ai.evil.com"}), "cn")
        self.assertEqual(converter._realm_from({}), "cn")

    def test_explicit_realm_beats_domain(self):
        """桌面端切版本后 variant 已改成 ai、domain 还停在老域名，以 variant 为准。"""
        self.assertEqual(
            converter._realm_from({"variant": "ai", "domain": "www.codebuddy.cn"}), "global")

    def test_env_override_version_and_full_ua(self):
        import os

        os.environ["WB_UA_VERSION"] = "9.9.9"
        try:
            self.assertIn("WorkBuddy/9.9.9", converter._official_user_agent("", "cn"))
        finally:
            del os.environ["WB_UA_VERSION"]
        os.environ["WB_UA"] = "Custom/1.0"
        try:
            self.assertEqual(converter._official_user_agent("6.0.0", "global"), "Custom/1.0")
        finally:
            del os.environ["WB_UA"]


class ChatEndpointTests(unittest.TestCase):
    """chat 端点必须按账号版本分域。"""

    class _Cred:
        def __init__(self, realm, domain):
            self._realm, self._domain = realm, domain

        def summary(self):
            return {"realm": self._realm, "domain": self._domain}

    def test_cn_and_global_endpoints(self):
        self.assertEqual(converter.chat_endpoint(self._Cred("cn", "www.codebuddy.cn")),
                         "https://copilot.tencent.com/v2/chat/completions")
        self.assertEqual(converter.chat_endpoint(self._Cred("global", "www.workbuddy.ai")),
                         "https://www.workbuddy.ai/v2/chat/completions")

    def test_falls_back_to_cn(self):
        class Boom:
            def summary(self):
                raise RuntimeError("boom")

        self.assertIn("copilot.tencent.com", converter.chat_endpoint(None))
        self.assertIn("copilot.tencent.com", converter.chat_endpoint(Boom()))

    def test_env_override(self):
        """国际版主机是从「国内 token 被国际主机拒绝」反推的，留了逃生口。"""
        import os

        os.environ["WB_CHAT_BASE"] = "https://www.codebuddy.ai/"
        try:
            self.assertEqual(converter.chat_endpoint(self._Cred("global", "www.workbuddy.ai")),
                             "https://www.codebuddy.ai/v2/chat/completions")
        finally:
            del os.environ["WB_CHAT_BASE"]


class SystemFirstTests(unittest.TestCase):
    """国际版端点要求首条消息是 system，否则 11128 "first message is not system prompt"。

    这与渠道校验那个 11128 是同一个业务码、完全不同的一条规则：国内端点不要求。
    实测（真实国际版账号）空 system 可以通过，所以补的是空 system。
    """

    class _Cred:
        def __init__(self, realm):
            self._realm = realm

        def summary(self):
            return {"realm": self._realm, "domain": "x"}

    USR = {"role": "user", "content": "hi"}

    def test_global_prepends_empty_system(self):
        body = {"messages": [self.USR]}
        out = converter.ensure_system_first(body, self._Cred("global"))
        self.assertEqual(len(out["messages"]), 2)
        self.assertEqual(out["messages"][0], {"role": "system", "content": ""})
        self.assertEqual(out["messages"][1], self.USR)
        # 原对象不能被改：同一份 body 可能还被日志/重试用到
        self.assertEqual(len(body["messages"]), 1)

    def test_global_keeps_existing_system(self):
        original = [{"role": "system", "content": "You are helpful."}, self.USR]
        out = converter.ensure_system_first({"messages": original}, self._Cred("global"))
        self.assertIs(out["messages"], original)
        self.assertEqual(len(out["messages"]), 2)

    def test_cn_is_untouched(self):
        body = {"messages": [self.USR]}
        self.assertIs(converter.ensure_system_first(body, self._Cred("cn")), body)

    def test_empty_or_broken_input_is_safe(self):
        cred = self._Cred("global")
        for body in ({}, {"messages": []}, {"messages": None}, {"messages": "x"}):
            self.assertIs(converter.ensure_system_first(body, cred), body)
        self.assertEqual(converter.ensure_system_first("not a dict", cred), "not a dict")


class ConversationHeadersTests(unittest.TestCase):
    def test_all_three_headers_present(self):
        headers = converter.conversation_headers("uid-1", "session-a", "msg-1")
        for key in CHANNEL_KEYS:
            self.assertIn(key, headers)
            self.assertTrue(headers[key])

    def test_same_conversation_keeps_conversation_id(self):
        first = converter.conversation_headers("uid-1", "session-a", "msg-1")
        second = converter.conversation_headers("uid-1", "session-a", "msg-2")
        self.assertEqual(first["X-Conversation-ID"], second["X-Conversation-ID"])
        # 请求与消息 id 必须换新，否则每轮都自称"同一个请求"
        self.assertNotEqual(first["X-Conversation-Request-ID"], second["X-Conversation-Request-ID"])
        self.assertNotEqual(first["X-Conversation-Message-ID"], second["X-Conversation-Message-ID"])

    def test_different_conversations_do_not_collide(self):
        a = converter.conversation_headers("uid-1", "session-a")
        b = converter.conversation_headers("uid-1", "session-b")
        self.assertNotEqual(a["X-Conversation-ID"], b["X-Conversation-ID"])

    def test_same_account_different_accounts_differ(self):
        a = converter.conversation_headers("uid-1", "session-a")
        b = converter.conversation_headers("uid-2", "session-a")
        self.assertNotEqual(a["X-Conversation-ID"], b["X-Conversation-ID"])

    def test_ids_are_uuid_shaped(self):
        import uuid

        for value in converter.conversation_headers("u", "s", "m").values():
            self.assertEqual(str(uuid.UUID(value)), value)

    def test_missing_keys_still_produce_headers(self):
        """调用方没给会话线索时也必须出三枚头（宁可每次新 id，不能缺）。"""
        headers = converter.conversation_headers()
        for key in CHANNEL_KEYS:
            self.assertTrue(headers.get(key))


class BuildHeadersTests(unittest.TestCase):
    """`build_headers` 是两个 store 共用的唯一入口。"""

    AUTH = {"accessToken": "plain-token", "domain": "www.codebuddy.cn"}
    ACCOUNT = {"uid": "uid-1", "enterpriseId": ""}

    def test_identity_and_channel_headers(self):
        headers = converter.build_headers(self.AUTH, self.ACCOUNT)
        self.assertEqual(headers["Authorization"], "Bearer plain-token")
        self.assertEqual(headers["X-User-Id"], "uid-1")
        self.assertEqual(headers["User-Agent"], converter.USER_AGENT)
        for key in CHANNEL_KEYS:
            self.assertIn(key, headers)

    def test_channels_can_be_disabled_for_plugin_calls(self):
        """刷新 token 走插件域，不是 chat 域，不该带会话头。"""
        headers = converter.build_headers(self.AUTH, self.ACCOUNT, channels=False)
        for key in CHANNEL_KEYS:
            self.assertNotIn(key, headers)

    def test_empty_uid_still_gets_headers(self):
        headers = converter.build_headers(self.AUTH, {})
        for key in CHANNEL_KEYS:
            self.assertTrue(headers.get(key))


class RequestOverrideTests(unittest.TestCase):
    """池中间件通过 ContextVar 覆盖会话头，凭据层据此发头。"""

    def test_override_replaces_and_restores(self):
        self.assertIsNone(converter.REQUEST_CHANNELS.get())
        channels = converter.conversation_headers("uid-1", "session-a", "msg-1")
        token = converter.REQUEST_CHANNELS.set(channels)
        try:
            self.assertEqual(converter.REQUEST_CHANNELS.get(), channels)
        finally:
            converter.REQUEST_CHANNELS.reset(token)
        self.assertIsNone(converter.REQUEST_CHANNELS.get())


class SwitchStoreHeaderTests(unittest.TestCase):
    """switch 账号库那条路的 store 也必须吃到 ContextVar 覆盖。

    这一条最容易漏：它的 `get_headers` 是**另一份实现**（admin/switch_store.py），
    只改 converter 的 CredentialManager 时，线上跑的那条路（WB-Switch-Plus）
    仍然不带会话头 —— 表现就是「改了没效果」。
    """

    def test_switch_store_get_headers_applies_override(self):
        import tempfile

        from admin.switch_store import SwitchStore

        with tempfile.TemporaryDirectory() as tmp:
            accounts = Path(tmp) / "accounts.json"
            accounts.write_text("[]", encoding="utf-8")
            store = SwitchStore(tmp, str(accounts), "", "x" * 24)
            manager = store.manager_for("aid", {"file": "x.info"})
            manager._session = lambda: {  # type: ignore[method-assign]
                "auth": {"accessToken": "tok", "domain": "www.codebuddy.cn",
                         "expiresAt": 4102444800000},
                "account": {"uid": "uid-1"},
            }
            manager._is_expired = lambda: False  # type: ignore[method-assign]
            channels = converter.conversation_headers("uid-1", "session-a", "msg-1")
            token = converter.REQUEST_CHANNELS.set(channels)
            try:
                headers = manager.get_headers()
            finally:
                converter.REQUEST_CHANNELS.reset(token)
        for key in CHANNEL_KEYS:
            self.assertEqual(headers.get(key), channels[key])


class AccountRealmTests(unittest.TestCase):
    """`account_realm()`：版本必须从凭据取，不能只看账号行。

    两个 store 写进 state.json 的账号行只有 file / name / created / enabled，
    不含版本字段。以前直接 `realm_of(item)` 于是一律判成国内版，国际版账号
    会拿国内账单地址查积分 → 401 → 整号进冷却 → 界面上只显示「积分服务请求失败」。
    """

    class _Manager:
        def __init__(self, summary):
            self._summary = summary

        def summary(self):
            if isinstance(self._summary, Exception):
                raise self._summary
            return self._summary

    def test_uses_credential_not_account_row(self):
        from admin.pool import account_realm

        item = {"file": "x.info", "name": "n", "enabled": True}  # 无版本字段
        cred = self._Manager({"realm": "global", "domain": "www.workbuddy.ai"})
        self.assertEqual(account_realm(item, cred), "global")

    def test_cn_stays_cn(self):
        from admin.pool import account_realm

        cred = self._Manager({"realm": "cn", "domain": "www.codebuddy.cn"})
        self.assertEqual(account_realm({"file": "x"}, cred), "cn")

    def test_falls_back_to_item_then_cn(self):
        from admin.pool import account_realm

        self.assertEqual(account_realm({"variant": "ai"}, None), "global")
        self.assertEqual(account_realm({"file": "x"}, None), "cn")

    def test_summary_failure_does_not_raise(self):
        from admin.pool import account_realm

        cred = self._Manager(RuntimeError("凭据损坏"))
        self.assertEqual(account_realm({"file": "x"}, cred), "cn")


class FalsePositiveRewriteTests(unittest.TestCase):
    """上游把 dsh 的 `@` 文件引用说明误判成非官方客户端，回 11128。

    实测（同一份 15.8K system）：原样 11128、删掉那句 200、同义改写 200。
    这里只改 system/developer，绝不动 user/assistant 的内容。
    """

    SENT = ("Relative paths resolve from the workspace root; "
            "absolute paths identify files or directories on the host.")

    def test_rewrites_system(self):
        body = {"messages": [{"role": "system", "content": "a " + self.SENT + " b"}]}
        out = converter.defang_false_positives(body)
        self.assertIn("resolved against the workspace root", out["messages"][0]["content"])
        self.assertNotIn(self.SENT, out["messages"][0]["content"])

    def test_does_not_touch_user_or_assistant(self):
        body = {"messages": [
            {"role": "user", "content": self.SENT},
            {"role": "assistant", "content": self.SENT},
        ]}
        out = converter.defang_false_positives(body)
        self.assertEqual(out, body)

    def test_handles_content_blocks(self):
        body = {"messages": [{"role": "system", "content": [
            {"type": "text", "text": self.SENT}, {"type": "text", "text": "keep"}]}]}
        out = converter.defang_false_positives(body)
        self.assertIn("resolved against", out["messages"][0]["content"][0]["text"])
        self.assertEqual(out["messages"][0]["content"][1]["text"], "keep")

    def test_no_match_returns_same_object(self):
        body = {"messages": [{"role": "system", "content": "nothing to see"}]}
        self.assertIs(converter.defang_false_positives(body), body)

    def test_env_can_disable(self):
        import os

        body = {"messages": [{"role": "system", "content": self.SENT}]}
        os.environ["CODEBUDDY_NO_PROMPT_REWRITE"] = "1"
        try:
            self.assertIs(converter.defang_false_positives(body), body)
        finally:
            del os.environ["CODEBUDDY_NO_PROMPT_REWRITE"]

    def test_survives_broken_input(self):
        for body in ({}, {"messages": None}, {"messages": "x"}, "not a dict"):
            converter.defang_false_positives(body)  # 不抛即可


if __name__ == "__main__":
    unittest.main()
