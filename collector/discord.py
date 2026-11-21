"""
Discord への通知（Webhook）。secwatch と FW・EOLウォッチの両方から使う。

  DISCORD_WEBHOOK     … 送り先チャンネルの Webhook URL（Secrets に登録）
  DISCORD_WEBHOOK_FW  … FW・EOLウォッチだけ別チャンネルにしたいときの URL（任意。未設定なら DISCORD_WEBHOOK）
  DISCORD_MIN_CVSS    … secwatch のうち Discord に送る最低 CVSS（任意。未設定なら通知対象をすべて送る）
  DISCORD_MENTION     … 特に重要なもの（KEV・CVSS 9以上・EOL 30日以内）に付けるメンション（任意）
                         例: @everyone / <@123456789012345678>（自分のユーザーID）
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

UA = "secwatch/1.0 (+personal advisory monitor)"

COLOR = {"kev": 0x7C3AED, "CRITICAL": 0xC42B2B, "HIGH": 0xE05A1A, "MEDIUM": 0xC08A00,
         "LOW": 0x2F855A, "info": 0x5865F2, "eol": 0xC42B2B, "eol_soon": 0xE05A1A, "release": 0x16A34A}


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def webhook(kind: str = "sec") -> str:
    if kind == "fw" and _env("DISCORD_WEBHOOK_FW"):
        return _env("DISCORD_WEBHOOK_FW")
    return _env("DISCORD_WEBHOOK")


def enabled(kind: str = "sec") -> bool:
    return bool(webhook(kind))


def _mention(urgent: bool) -> tuple[str, dict]:
    m = _env("DISCORD_MENTION")
    if not (urgent and m):
        return "", {"parse": []}
    allowed = {"parse": []}
    if "@everyone" in m or "@here" in m:
        allowed["parse"].append("everyone")
    ids = re.findall(r"<@!?(\d+)>", m)
    if ids:
        allowed["users"] = ids
    return m + " ", allowed


def send(kind: str, content: str, embed: dict, username: str, avatar: str = "", urgent: bool = False, log=print) -> bool:
    """1件 = 1メッセージで送る（スマホにはメッセージごとに通知が届く）"""
    url = webhook(kind)
    if not url:
        return False
    mention, allowed = _mention(urgent)
    body = {"username": username, "content": (mention + content)[:1900], "embeds": [embed], "allowed_mentions": allowed}
    if avatar:
        body["avatar_url"] = avatar
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            time.sleep(0.8)  # Webhook の送信間隔（連投で制限されないように）
            return True
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:  # 送りすぎ → 指定された秒数だけ待って再送
                try:
                    wait = float(json.loads(e.read()).get("retry_after", 2))
                except Exception:  # noqa: BLE001
                    wait = 2.0
                time.sleep(min(wait, 30) + 0.5)
                continue
            detail = e.read().decode("utf-8", "replace")[:200] if e.code != 429 else ""
            log(f"  Discord送信失敗 HTTP {e.code} {detail}")
            if e.code in (401, 403, 404):
                log("  → Webhook URL が正しいか、削除されていないか確認してください")
            return False
        except Exception as e:  # noqa: BLE001
            log(f"  Discord送信失敗: {e}")
            return False
    return False


def clip(s: str, n: int) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"
