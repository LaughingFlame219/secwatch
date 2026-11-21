#!/usr/bin/env python3
"""
secwatch mobile - GitHub Actions で定期実行する収集スクリプト

  1. 各ベンダーのアドバイザリを収集（Palo Alto / Fortinet / Cisco / Arista / Juniper）
  2. アドバイザリページ・NVD で CVE と CVSS を補完、CISA KEV と照合
  3. タイトルと概要を日本語に機械翻訳（Argos Translate。DeepL Free も選べる）
  4. ntfy でスマホへプッシュ（タップするとアプリの詳細画面が開く）
  5. docs/data/advisories.json に書き出し → GitHub Pages のアプリが読む

環境変数（GitHub の Secrets / Variables で設定）
  NTFY_TOPIC       … 通知先トピック（未設定なら通知なし）
  NTFY_SERVER      … 既定 https://ntfy.sh
  NTFY_TOKEN       … ntfy のアクセストークン（任意）
  APP_URL          … アプリのURL（例 https://yourname.github.io/secwatch-mobile/）
  NVD_API_KEY      … 任意
  DEEPL_API_KEY    … 任意。DeepL API Free のキー（末尾 :fx）。未設定なら Argos Translate で翻訳
  TRANSLATE_DISABLE… 1 にすると翻訳しない
  NOTIFY_MIN_CVSS / NOTIFY_KEYWORDS / NOTIFY_EXCLUDE / NOTIFY_VENDORS … 通知ルールの上書き
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secwatch_lib as lib  # noqa: E402
from translate import Translator  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "collector", "config.json")
STATE = os.path.join(ROOT, "state", "state.json")
OUT = os.path.join(ROOT, "docs", "data", "advisories.json")

VENDOR_NAME = {"PaloAlto": "Palo Alto", "Fortinet": "Fortinet", "Cisco": "Cisco",
               "Arista": "Arista", "Juniper": "Juniper"}
PUBLIC_FIELDS = ["uid", "vendor", "adv_id", "title", "url", "published", "updated", "severity", "cvss",
                 "cvss_version", "cvss_vector", "cvss_source", "cves", "kev", "kev_date", "summary",
                 "ja", "first_seen"]

log = lib.log


def now_iso() -> str:
    return lib.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def date_of(a: dict) -> str:
    return a.get("published") or a.get("first_seen") or ""


# ----------------------------------------------------------------------------
# 状態ファイル
# ----------------------------------------------------------------------------
def load_state() -> tuple[dict, bool]:
    if not os.path.exists(STATE):
        return {"advisories": {}, "nvd_cache": {}, "runs": []}, True
    with open(STATE, encoding="utf-8") as f:
        st = json.load(f)
    st.setdefault("advisories", {})
    st.setdefault("nvd_cache", {})
    st.setdefault("runs", [])
    return st, False


def save_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    os.replace(tmp, path)


def upsert(advs: dict, vendor: str, it: dict) -> tuple[dict, bool]:
    uid = f"{vendor}:{it['adv_id']}"
    h = hashlib.sha1(json.dumps([it["title"], it["updated"], it["cvss"], it["severity"], it["cves"]],
                                sort_keys=True).encode()).hexdigest()
    a = advs.get(uid)
    if a is None:
        a = {
            "uid": uid, "vendor": vendor, "adv_id": it["adv_id"], "title": it["title"], "url": it["url"],
            "published": it["published"], "updated": it["updated"], "severity": it["severity"],
            "cvss": it["cvss"], "cvss_version": it["cvss_version"], "cvss_vector": it["cvss_vector"],
            "cvss_source": "vendor" if it["cvss"] is not None else "", "cves": list(it["cves"]),
            "kev": False, "kev_date": "", "summary": (it["summary"] or "")[:800], "ja": None,
            "first_seen": now_iso(),
            # 内部用
            "_hash": h, "_notified": False, "_notified_kev": False, "_scraped": False,
        }
        advs[uid] = a
        return a, True
    if a.get("_hash") != h:
        a["_hash"] = h
        a["title"], a["url"] = it["title"] or a["title"], it["url"] or a["url"]
        a["updated"] = it["updated"] or a["updated"]
        if it["published"] and not a["published"]:
            a["published"] = it["published"]
        if it["severity"]:
            a["severity"] = it["severity"]
        if it["cvss"] is not None:
            a.update(cvss=it["cvss"], cvss_version=it["cvss_version"], cvss_vector=it["cvss_vector"],
                     cvss_source="vendor")
        if it["cves"]:
            a["cves"] = sorted(set(a["cves"]) | set(it["cves"]))
        if it["summary"]:
            a["summary"] = it["summary"][:800]
    return a, False


# ----------------------------------------------------------------------------
# ページ取得（CVE / CVSS / 日付 / 概要の補完）
# ----------------------------------------------------------------------------
_page_cache: dict[str, str] = {}


def page_text(url: str) -> str:
    if not url.startswith("http"):
        return ""
    if url not in _page_cache:
        try:
            raw = lib.http_get(url, timeout=25).decode("utf-8", "replace")
            raw = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", raw)
            _page_cache[url] = lib.strip_tags(raw)
        except Exception as e:  # noqa: BLE001
            log(f"  ページ取得失敗 {url}: {e}")
            _page_cache[url] = ""
    return _page_cache[url]


def enrich_from_page(a: dict) -> None:
    text = page_text(a["url"])
    a["_scraped"] = True
    if not text:
        return
    if not a["cves"]:
        a["cves"] = sorted(set(lib.CVE_RE.findall(text)))[:30]
    if len(a.get("summary") or "") < 80:  # フィードに概要がない場合、ページ本文の冒頭を概要にする
        head = a["title"][:40]
        i = text.find(head) if head else -1
        body = text[i + len(a["title"]):] if i >= 0 else text
        m = re.search(r"(?:Summary|Description|概要)\s*[:：]?\s*(.{60,600}?[.。])(?:\s|$)", body)
        a["summary"] = (m.group(1) if m else body[:400]).strip()[:600]
    if a["cvss"] is None:
        for r in lib.PAGE_SCORE_RES:
            m = r.search(text)
            if m and 0 <= float(m.group(1)) <= 10:
                a["cvss"], a["cvss_source"] = float(m.group(1)), "page"
                a["severity"] = a["severity"] or lib.sev_from_score(a["cvss"])
                break
    if not a["published"]:
        m = lib.DATE_RE.search(text)
        if m:
            try:
                a["published"] = dt.datetime.strptime(re.sub(r"\s+", " ", m.group(0)),
                                                      "%B %d, %Y").strftime("%Y-%m-%dT00:00:00Z")
            except ValueError:
                pass


# ----------------------------------------------------------------------------
# NVD / KEV
# ----------------------------------------------------------------------------
def nvd_lookup(cve: str, cache: dict, budget: list) -> dict | None:
    c = cache.get(cve)
    if c and c.get("cvss") is not None:
        return c
    if c and (lib.utcnow() - dt.datetime.fromisoformat(c["at"])).days < 3:
        return None
    if budget[0] <= 0:
        return None
    budget[0] -= 1
    key = env("NVD_API_KEY")
    time.sleep(0.7 if key else 6.5)
    try:
        data = json.loads(lib.http_get(f"{lib.NVD_URL}?cveId={cve}", headers={"apiKey": key} if key else None))
    except Exception as e:  # noqa: BLE001
        log(f"  NVD取得失敗 {cve}: {e}")
        return None
    res = {"cvss": None, "version": "", "vector": "", "at": lib.utcnow().isoformat(timespec="seconds")}
    vulns = data.get("vulnerabilities") or []
    if vulns:
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            arr = metrics.get(k) or []
            if arr:
                prim = next((m for m in arr if m.get("type") == "Primary"), arr[0])
                cd = prim.get("cvssData", {})
                res.update(cvss=cd.get("baseScore"), version=cd.get("version", ""), vector=cd.get("vectorString", ""))
                break
    cache[cve] = res
    return res if res["cvss"] is not None else None


def load_kev() -> dict:
    data = json.loads(lib.http_get(env("KEV_URL", lib.KEV_URL), timeout=60))
    return {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}


# ----------------------------------------------------------------------------
# 通知 (ntfy)
# ----------------------------------------------------------------------------
def app_url() -> str:
    u = env("APP_URL")
    if not u and env("GITHUB_REPOSITORY"):
        owner, repo = env("GITHUB_REPOSITORY").split("/", 1)
        u = f"https://{owner}.github.io/{repo}/"
    return (u.rstrip("/") + "/sec/") if u else ""


def deep_link(a: dict) -> str:
    base = app_url()
    return f"{base}#/a/{urllib.parse.quote(a['uid'], safe='')}" if base else a["url"]


def push(payload: dict) -> bool:
    topic = env("NTFY_TOPIC")
    if not topic:
        log(f"  [通知:未設定のため表示のみ] {payload.get('title')} / {payload.get('message', '')[:80]}")
        return True
    payload = dict(payload, topic=topic)
    base = app_url()
    if base:
        payload.setdefault("icon", base + "icon-192.png")
    hdr = {"Content-Type": "application/json", "User-Agent": lib.UA}
    if env("NTFY_TOKEN"):
        hdr["Authorization"] = f"Bearer {env('NTFY_TOKEN')}"
    req = urllib.request.Request(env("NTFY_SERVER", "https://ntfy.sh").rstrip("/") + "/",
                                 data=json.dumps(payload).encode("utf-8"), headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        return True
    except Exception as e:  # noqa: BLE001
        log(f"  通知送信失敗: {e}")
        return False


def push_advisory(a: dict, kev_added: bool = False) -> bool:
    score = a["cvss"]
    sev = (a["severity"] or lib.sev_from_score(score) or "").upper()
    prio = 5 if (a["kev"] or (score or 0) >= 9) else 4 if (score or 0) >= 7 or sev in ("CRITICAL", "HIGH") else 3
    tag = "rotating_light" if a["kev"] else {"CRITICAL": "red_circle", "HIGH": "orange_circle",
                                            "MEDIUM": "yellow_circle"}.get(sev, "white_circle")
    parts = [VENDOR_NAME.get(a["vendor"], a["vendor"])]
    parts.append(f"CVSS {score:.1f}" if score is not None else (sev or "スコア未発表"))
    if a["kev"]:
        parts.append("悪用確認済み")
    title = " · ".join(parts)
    ja = a.get("ja") or {}
    head = ("【CISA KEVに追加】" if kev_added else "") + (ja.get("title") or a["title"])
    excerpt = (ja.get("summary") or a["summary"] or "").strip()
    if excerpt.lower().startswith(a["title"].lower()[:40]) or excerpt.startswith((ja.get("title") or "\0")[:20]):
        excerpt = ""
    message = f"{head}\n{excerpt[:200]}" if excerpt else head
    return push({"title": title, "message": message[:1000], "priority": prio, "tags": [tag],
                 "click": deep_link(a),
                 "actions": [{"action": "view", "label": "原文", "url": a["url"]}] if a["url"].startswith("http") else []})


# ----------------------------------------------------------------------------
def ja_source(a: dict) -> tuple[str, str, str]:
    """翻訳する原文（タイトル・概要）と、その変更検知用ハッシュ"""
    limit = int(CFG.get("translate", {}).get("summary_chars", 600))
    summ = (a.get("summary") or "").strip()
    if summ.lower().startswith(a["title"].lower()[:40]) and len(summ) <= len(a["title"]) + 5:
        summ = ""
    summ = summ[:limit]
    h = hashlib.sha1(f"{a['title']}\n{summ}".encode()).hexdigest()[:12]
    return a["title"], summ, h


def rule_from_env(rule: dict) -> dict:
    r = dict(rule)
    if env("NOTIFY_MIN_CVSS"):
        r["min_cvss"] = float(env("NOTIFY_MIN_CVSS"))
    for k, name in (("keywords", "NOTIFY_KEYWORDS"), ("exclude_keywords", "NOTIFY_EXCLUDE"),
                    ("vendors", "NOTIFY_VENDORS")):
        if env(name):
            r[k] = [x.strip() for x in env(name).split(",") if x.strip()]
    return r


def main() -> int:
    global CFG
    with open(CONFIG, encoding="utf-8") as f:
        CFG = json.load(f)
    if env("SOURCES_OVERRIDE"):  # テスト用
        CFG["sources"] = json.loads(env("SOURCES_OVERRIDE"))
    st, first_run = load_state()
    advs: dict = st["advisories"]
    runs = []

    # 1) 収集
    for src in CFG["sources"]:
        if not src.get("enabled", True):
            continue
        vendor = src["vendor"]
        attempts = [src] + [dict(src, **fb) for fb in lib._as_list(src.get("fallback"))]
        items, err = None, ""
        for at in attempts:
            try:
                items = lib.PARSERS[at["type"]](lib.http_get(at["url"], timeout=45), at)
                break
            except Exception as e:  # noqa: BLE001
                err = f"{e}"
                log(f"[{vendor}] 取得失敗 {at['url']}: {e}")
        if items is None:
            runs.append({"vendor": vendor, "ok": False, "count": 0, "new": 0, "error": err[:200], "at": now_iso()})
            continue
        new = 0
        for it in items:
            _, is_new = upsert(advs, vendor, it)
            new += is_new
        runs.append({"vendor": vendor, "ok": True, "count": len(items), "new": new, "error": "", "at": now_iso()})
        log(f"[{vendor}] {len(items)}件 / 新規 {new}件")

    by_new = sorted(advs.values(), key=lambda a: (a["first_seen"], date_of(a)), reverse=True)
    src_by_vendor = {s["vendor"]: s for s in CFG["sources"]}

    # 2) ページから補完
    budget = int(CFG["scrape_max_per_run"])
    for a in by_new:
        if budget <= 0:
            break
        if a["_scraped"] or not src_by_vendor.get(a["vendor"], {}).get("scrape_page"):
            continue
        if a["cvss"] is not None and a["cves"] and a["published"] and len(a["summary"] or "") >= 80:
            a["_scraped"] = True
            continue
        budget -= 1
        enrich_from_page(a)
        time.sleep(0.5)

    # 3) NVD
    nb = [int(env("NVD_MAX_PER_RUN", str(CFG["nvd_max_per_run"])))]
    for a in by_new:
        if a["cvss"] is None and a["cves"]:
            best = None
            for cve in a["cves"][:8]:
                r = nvd_lookup(cve, st["nvd_cache"], nb)
                if r and (best is None or r["cvss"] > best["cvss"]):
                    best = r
            if best:
                a.update(cvss=best["cvss"], cvss_version=best["version"], cvss_vector=best["vector"], cvss_source="nvd")
                a["severity"] = a["severity"] or lib.sev_from_score(best["cvss"])

    # 4) KEV
    try:
        kev = load_kev()
        log(f"[KEV] {len(kev)}件")
        for a in advs.values():
            hits = [kev[c] for c in a["cves"] if c in kev]
            if hits and not a["kev"]:
                a["kev"], a["kev_date"] = True, min(hits)
    except Exception as e:  # noqa: BLE001
        log(f"[KEV] 取得失敗: {e}")

    # 通知対象を先に決める
    rule = rule_from_env(CFG["notify"]["rule"])
    cutoff = (lib.utcnow() - dt.timedelta(days=int(CFG["notify"]["max_age_days"]))).strftime("%Y-%m-%dT%H:%M:%SZ")

    def flat(a):  # matches_rule 用
        return dict(a, summary=a["summary"] or "", kev=1 if a["kev"] else 0)

    to_notify = [a for a in advs.values() if not a["_notified"] and date_of(a) >= cutoff and lib.matches_rule(flat(a), rule)]
    to_notify.sort(key=lambda a: (a["kev"], a["cvss"] or 0), reverse=True)
    kev_added = [a for a in advs.values() if a["kev"] and a["_notified"] and not a["_notified_kev"]]

    # 5) 日本語訳（通知対象 → 最近のもの の順。翻訳元が変わったら訳し直す）
    tr = Translator(log, st)
    n_tr = 0
    if tr.enabled:
        tcfg = CFG.get("translate", {})
        back = (lib.utcnow() - dt.timedelta(days=int(tcfg.get("backfill_days", 30)))).strftime("%Y-%m-%dT%H:%M:%SZ")
        queue, seen = [], set()
        for a in to_notify + kev_added + sorted((a for a in advs.values() if date_of(a) >= back),
                                                key=date_of, reverse=True):
            src = ja_source(a)
            if a["uid"] in seen or (a.get("ja") and a["ja"].get("src") == src[2]):
                continue
            seen.add(a["uid"])
            queue.append((a, src))
        queue = queue[: int(tcfg.get("max_per_run", 40))]
        for i in range(0, len(queue), 10):
            batch = queue[i:i + 10]
            texts = [t for _, (title, summ, _) in batch for t in (title, summ)]
            out = tr.translate(texts)
            if out is None:
                break
            for j, (a, (title, summ, h)) in enumerate(batch):
                a["ja"] = {"title": out[2 * j].strip(), "summary": out[2 * j + 1].strip() if summ else "",
                           "engine": tr.engine, "src": h}
                n_tr += 1
        if n_tr:
            log(f"翻訳: {n_tr}件（{tr.engine}）")
    else:
        log("翻訳は無効です")

    # 6) 通知
    sent = 0
    if first_run and not env("NOTIFY_INITIAL"):
        log(f"初回実行のため通知はスキップ（対象 {len(to_notify)}件）")
    else:
        limit = int(CFG["notify"]["max_push_per_run"])
        for a in to_notify[:limit]:
            sent += push_advisory(a)
        rest = to_notify[limit:]
        if rest:
            push({"title": f"ほか {len(rest)}件の新しいアドバイザリ",
                  "message": "、".join(f"{VENDOR_NAME.get(a['vendor'], a['vendor'])} {a['adv_id']}" for a in rest[:10]),
                  "priority": 3, "tags": ["bell"], "click": app_url() or "https://ntfy.sh"})
        for a in kev_added[:limit]:
            sent += push_advisory(a, kev_added=True)
    for a in advs.values():
        a["_notified"] = True
        if a["kev"]:
            a["_notified_kev"] = True

    # 7) 古いものを整理して書き出し
    keep = (lib.utcnow() - dt.timedelta(days=int(CFG["keep_days"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
    for uid in [u for u, a in advs.items() if date_of(a) < keep and a["first_seen"] < keep]:
        del advs[uid]
    st.pop("runs", None)
    public = sorted(({k: a.get(k) for k in PUBLIC_FIELDS} for a in advs.values()), key=date_of, reverse=True)
    # 中身が変わったときだけ書き出す（毎回コミットしてリポジトリが膨らむのを防ぐ）
    digest = hashlib.sha1(json.dumps([public, [(r["vendor"], r["ok"], r["count"]) for r in runs]],
                                     ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    if digest != st.get("out_hash") or not os.path.exists(OUT):
        save_json(OUT, {"generated": now_iso(), "runs": runs, "advisories": public})
        st["out_hash"] = digest
        log("アプリ用データを更新")
    else:
        log("アプリ用データに変更なし")
    save_json(STATE, st)

    msg = f"完了: {len(advs)}件保持 / 翻訳 {n_tr}件 / 通知 {sent}件"
    log(msg)
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as f:
            f.write(f"### secwatch\n{msg}\n\n| ベンダー | 結果 | 件数 | 新規 |\n|---|---|---|---|\n")
            for r in runs:
                f.write(f"| {r['vendor']} | {'✅' if r['ok'] else '❌ ' + r['error'][:80]} | {r['count']} | {r['new']} |\n")
    return 0


CFG: dict = {}

if __name__ == "__main__":
    sys.exit(main())
