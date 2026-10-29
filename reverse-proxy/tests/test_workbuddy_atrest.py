"""issue #23：WorkBuddy 5.6.0 $wbEncrypted 加密登录态支持测试（离线自洽，不读真实 auth）。"""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.workbuddy_atrest_crypto import (  # noqa: E402
    decrypt_auth_field,
    encrypt_auth_field,
    is_encrypted_field,
)

# 44 字符 canonical base64 == 32 字节，仅用于测试（与真实密钥无关）
TEST_SECRET = base64.b64encode(hashlib.sha256(b"test-seed").digest()).decode()


@pytest.fixture(autouse=True)
def _test_secret(monkeypatch):
    monkeypatch.setenv("WORKBUDDY_AT_REST_SECRET", TEST_SECRET)


def test_plaintext_passthrough():
    """旧版明文 token 原样返回，不触发任何解密。"""
    assert decrypt_auth_field("abc.jwt.token") == "abc.jwt.token"
    assert decrypt_auth_field("") == ""
    assert not is_encrypted_field("abc")


def test_encrypt_decrypt_roundtrip():
    token = "eyJhbGciOiJSUzI1NiJ9.payload.signature"
    sealed = encrypt_auth_field(token)
    assert is_encrypted_field(sealed)
    assert sealed["$wbEncrypted"] == 1
    env = json.loads(base64.b64decode(sealed["envelope"]))
    assert env["suite"] == 1
    assert env["keyId"] == hashlib.sha256(
        hashlib.sha256(TEST_SECRET.encode()).digest()
    ).hexdigest()[:16]
    assert decrypt_auth_field(sealed) == token


def test_build_headers_from_encrypted_auth(tmp_path, monkeypatch):
    """CredentialManager 能对 $wbEncrypted 格式构建有效 Authorization（issue #23 场景）。"""
    from core.converter import CredentialManager

    session = {
        "auth": {
            "accessToken": encrypt_auth_field("access-token-plain"),
            "refreshToken": encrypt_auth_field("refresh-token-plain"),
            "domain": "www.workbuddy.cn",
            "expiresAt": 9999999999999,
        },
        "account": {"uid": "u1", "enterpriseId": "e1"},
    }
    f = tmp_path / "workbuddy-desktop.info"
    f.write_text(json.dumps(session), encoding="utf-8")
    cm = CredentialManager(f)
    h = cm.get_headers()
    assert h["Authorization"] == "Bearer access-token-plain"
    assert h["X-User-Id"] == "u1"


def test_get_headers_includes_channel_gate_headers(tmp_path):
    """get_headers() 合并渠道风控头（X-CodeBuddy-Request / 官方 UA / Origin 等）。"""
    from core.converter import CredentialManager

    session = {
        "auth": {
            "accessToken": "tok",
            "domain": "www.codebuddy.cn",
            "expiresAt": 9999999999999,
        },
        "account": {"uid": "u1", "enterpriseId": "e1"},
    }
    f = tmp_path / "workbuddy-desktop.info"
    f.write_text(json.dumps(session), encoding="utf-8")
    cm = CredentialManager(f)
    h = cm.get_headers()
    assert h["X-CodeBuddy-Request"] == "1"
    assert h["X-Requested-With"] == "XMLHttpRequest"
    assert "WorkBuddy" in h["User-Agent"]
    assert h["Origin"] == "https://www.codebuddy.cn"
    assert h["Referer"] == "https://www.codebuddy.cn/"
    assert "X-Machine-ID" in h
    assert "X-Session-ID" in h
    assert h["Authorization"] == "Bearer tok"
    assert h["X-User-Id"] == "u1"


def test_refresh_headers_keep_plugin_ua(tmp_path):
    """token 刷新路径（_build_headers_from）保留 plugin UA，不混入渠道头。"""
    from core.converter import CredentialManager

    session = {
        "auth": {
            "accessToken": "tok",
            "domain": "www.codebuddy.cn",
            "expiresAt": 9999999999999,
        },
        "account": {"uid": "u1", "enterpriseId": "e1"},
    }
    f = tmp_path / "workbuddy-desktop.info"
    f.write_text(json.dumps(session), encoding="utf-8")
    cm = CredentialManager(f)
    h = cm._build_headers_from(session["auth"], session["account"])
    assert h["User-Agent"] == "codebuddy2openai/2.0"
    assert "X-CodeBuddy-Request" not in h
