"""
英語 → 日本語の機械翻訳

  既定      : Argos Translate（オープンソース・オフライン。アカウント不要、完全無料）
  任意      : DeepL API Free（DEEPL_API_KEY を設定すると使用。月50万文字まで無料、超えると止まるだけ）

どちらも失敗した場合は翻訳なし（アプリは英語のまま表示）で処理を続ける。
"""
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

# 翻訳で崩れやすい語（CVE番号・バージョン・製品名）をDeepLでは保護する
PROTECT_RE = re.compile(
    r"CVE-\d{4}-\d{4,7}"
    r"|\b(?:PAN-OS|GlobalProtect|Prisma\s+\w+|Cortex\s+\w+|FortiOS|FortiGate|FortiProxy|FortiManager|FortiAnalyzer"
    r"|FortiWeb|FortiClient\w*|FortiSwitch|FortiAP|FortiSIEM|FortiSandbox|FortiMail|IOS\s+XE|IOS\s+XR|NX-OS|ASA|FTD"
    r"|Firepower|Meraki|Junos(?:\s+OS)?(?:\s+Evolved)?|SRX|EX|MX|QFX|PTX|EOS|CloudVision|VeloCloud|OpenConfig"
    r"|SSL-VPN|IPsec|BGP|OSPF|SNMP|HTTP/2|HTTPS?|TLS|SSH|DHCP|DNS|802\.1X|RADIUS|TACACS\+?)\b"
    r"|\b\d+(?:\.\d+){1,3}(?:-?[A-Za-z]+\d*)?\b"
    r"|\b[A-Z]{2,}(?:-[A-Z]{2,})*-\d+(?:-\d+)*\b"   # FG-IR-26-115, PAN-SA-2026-0001
    r"|\b[A-Z]{2,}\d{3,}\b"                         # JSA103900
    r"|\bcisco-sa-[\w-]+"
)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


class Translator:
    def __init__(self, log, state: dict):
        self.log = log
        self.state = state            # 月ごとの使用文字数などを保存（state.json の一部）
        self.engine = ""
        self.disabled_reason = ""
        self._argos = None
        key = _env("DEEPL_API_KEY")
        if key:
            if not key.endswith(":fx") and not _env("DEEPL_ALLOW_PRO"):
                self.disabled_reason = ("DEEPL_API_KEY が無料プラン（末尾 :fx）のキーではありません。"
                                        "課金を避けるため使いません。Argos Translate を使います")
                self.log(self.disabled_reason)
            else:
                self.engine = "deepl"
                self.key = key
                self.base = "https://api-free.deepl.com" if key.endswith(":fx") else "https://api.deepl.com"
                self.base = _env("DEEPL_ENDPOINT", self.base).rstrip("/")
        if not self.engine and not _env("TRANSLATE_DISABLE"):
            self.engine = "argos"

    # ------------------------------------------------------------------ DeepL
    def _deepl_usage_ok(self, chars: int) -> bool:
        import datetime as dt
        month = dt.date.today().strftime("%Y-%m")
        u = self.state.setdefault("deepl_usage", {})
        if u.get("month") != month:
            u.clear()
            u.update(month=month, chars=0)
        limit = int(_env("DEEPL_MONTHLY_LIMIT", "450000"))  # 無料枠50万の手前で止める
        if u["chars"] + chars > limit:
            return False
        u["chars"] += chars
        return True

    @staticmethod
    def _protect(text: str) -> str:
        esc = html.escape(text, quote=False)
        return PROTECT_RE.sub(lambda m: f"<x>{m.group(0)}</x>", esc)

    @staticmethod
    def _unprotect(text: str) -> str:
        return html.unescape(re.sub(r"</?x>", "", text))

    def _deepl(self, texts: list[str]) -> list[str]:
        chars = sum(len(t) for t in texts)
        if not self._deepl_usage_ok(chars):
            raise RuntimeError("今月のDeepL使用量が上限に近いため、翻訳を止めました")
        body = {"text": [self._protect(t) for t in texts], "source_lang": "EN", "target_lang": "JA",
                "tag_handling": "xml", "ignore_tags": ["x"]}
        req = urllib.request.Request(
            f"{self.base}/v2/translate", data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"DeepL-Auth-Key {self.key}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 456:
                raise RuntimeError("DeepLの無料枠を使い切りました（来月まで翻訳なし）") from e
            if e.code in (401, 403):
                raise RuntimeError("DeepLのAPIキーが正しくありません") from e
            raise
        return [self._unprotect(t["text"]) for t in data["translations"]]

    # ------------------------------------------------------------------ Argos
    def _argos_setup(self):
        if self._argos is not None:
            return self._argos
        try:
            import argostranslate.translate  # noqa: F401
        except ImportError:
            self.log("  Argos Translate をインストールしています（初回のみ時間がかかります）…")
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "argostranslate"], check=True)
        import argostranslate.package as pkg
        import argostranslate.translate as tr

        def find():
            for lang in tr.get_installed_languages():
                if lang.code == "en":
                    for t in lang.translations_from:
                        if t.to_lang.code == "ja":
                            return t
            return None

        t = find()
        if t is None:
            self.log("  英日翻訳モデルをダウンロードしています…")
            pkg.update_package_index()
            cand = [p for p in pkg.get_available_packages() if p.from_code == "en" and p.to_code == "ja"]
            if not cand:
                raise RuntimeError("Argos Translate の英日モデルが見つかりません")
            pkg.install_from_path(cand[0].download())
            t = find()
        if t is None:
            raise RuntimeError("Argos Translate の英日モデルを読み込めません")
        self._argos = t
        return t

    def _argos_translate(self, texts: list[str]) -> list[str]:
        t = self._argos_setup()
        return [t.translate(x) if x.strip() else "" for x in texts]

    # ------------------------------------------------------------------ 共通
    @property
    def enabled(self) -> bool:
        return bool(self.engine)

    def translate(self, texts: list[str]) -> list[str] | None:
        if not self.engine:
            return None
        try:
            if self.engine == "deepl":
                return self._deepl(texts)
            return self._argos_translate(texts)
        except Exception as e:  # noqa: BLE001
            self.log(f"  翻訳を停止: {e}")
            self.disabled_reason = str(e)
            self.engine = ""
            return None
