#!/usr/bin/env python3
"""
secwatch - ベンダーセキュリティアドバイザリ収集・通知・管理ツール

  python secwatch.py fetch            # 収集 → CVSS補完 → KEV照合 → 通知
  python secwatch.py serve            # Web画面 (http://127.0.0.1:8080)
  python secwatch.py list [--min 7]   # ターミナルで一覧
  python secwatch.py test-notify      # 通知先のテスト送信

Python 3.9+ / 標準ライブラリのみ
"""
from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import html
import json
import os
import re
import smtplib
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(BASE_DIR, "config.json")
UA = "secwatch/1.0 (+personal advisory monitor)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
STATUSES = ["未確認", "確認中", "対応中", "対応済", "影響なし"]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ----------------------------------------------------------------------------
# 共通
# ----------------------------------------------------------------------------
def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def log(msg: str) -> None:
    print(f"[{dt.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def http_get(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_post_json(url: str, payload: dict, timeout: int = 15) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": UA}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()


def to_iso(s: str | None) -> str:
    """RFC822 / ISO8601 どちらでも ISO8601(UTC) にそろえる"""
    if not s:
        return ""
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError):
        d = None
    if d is None:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return s
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sev_from_score(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def norm_sev(s: str | None) -> str:
    if not s:
        return ""
    s = s.strip().upper()
    return {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "INFO": "INFORMATIONAL"}.get(s, s)


def strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", html.unescape(s or ""))
    return re.sub(r"\s+", " ", s).strip()


# ----------------------------------------------------------------------------
# DB
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    uid          TEXT PRIMARY KEY,          -- vendor:id
    vendor       TEXT NOT NULL,
    adv_id       TEXT NOT NULL,
    title        TEXT,
    url          TEXT,
    published    TEXT,
    updated      TEXT,
    severity     TEXT,
    cvss         REAL,
    cvss_version TEXT,
    cvss_vector  TEXT,
    cvss_source  TEXT,                      -- vendor / nvd / page
    cves         TEXT,                      -- カンマ区切り
    kev          INTEGER DEFAULT 0,
    summary      TEXT,
    status       TEXT DEFAULT '未確認',
    memo         TEXT DEFAULT '',
    notified     INTEGER DEFAULT 0,
    notified_kev INTEGER DEFAULT 0,
    scraped      INTEGER DEFAULT 0,
    content_hash TEXT,
    first_seen   TEXT,
    last_seen    TEXT
);
CREATE INDEX IF NOT EXISTS idx_adv_pub ON advisories(published);
CREATE TABLE IF NOT EXISTS cve_cache (
    cve TEXT PRIMARY KEY, cvss REAL, version TEXT, vector TEXT, fetched TEXT
);
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY, date_added TEXT, ransomware TEXT, name TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, source TEXT, ok INTEGER,
    items INTEGER, new INTEGER, message TEXT
);
"""


def db_connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


# ----------------------------------------------------------------------------
# パーサ
#   どのパーサも dict のリストを返す:
#   adv_id, title, url, published, updated, severity, cvss, cvss_version,
#   cvss_vector, cves(list), summary
# ----------------------------------------------------------------------------
def _find_cvss(obj) -> list[dict]:
    """CVE JSON 5.x などの入れ子から cvssV* ブロックを再帰的に探す"""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.lower().startswith("cvssv") and isinstance(v, dict):
                if "baseScore" in v:
                    ver = v.get("version") or k[5:].replace("_", ".")
                    found.append(
                        {
                            "score": float(v["baseScore"]),
                            "version": str(ver),
                            "vector": v.get("vectorString", ""),
                            "severity": v.get("baseSeverity", ""),
                        }
                    )
            else:
                found.extend(_find_cvss(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_find_cvss(v))
    return found


def _pick_cvss(cands: list[dict], prefer: str = "4") -> dict | None:
    if not cands:
        return None
    pref = [c for c in cands if c["version"].startswith(prefer)]
    if pref:
        return max(pref, key=lambda c: c["score"])
    return max(cands, key=lambda c: (c["version"], c["score"]))


def parse_paloalto_json(raw: bytes, src: dict) -> list[dict]:
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("data") or data.get("advisories") or data.get("items") or [data]
    prefer = str(src.get("prefer_cvss", "4"))
    out = []
    for rec in data:
        if not isinstance(rec, dict):
            continue
        meta = rec.get("cveMetadata", {})
        cna = rec.get("containers", {}).get("cna", {})
        adv_id = meta.get("cveId") or rec.get("ID") or rec.get("id") or rec.get("advisory_id")
        if not adv_id:
            continue
        title = cna.get("title") or rec.get("title") or adv_id
        cv = _pick_cvss(_find_cvss(rec), prefer)
        sev = norm_sev((cv or {}).get("severity") or rec.get("severity"))
        if not sev and cv:
            sev = sev_from_score(cv["score"])
        desc = ""
        for d in cna.get("descriptions", []) or []:
            if d.get("lang", "en").startswith("en"):
                desc = d.get("value", "")
                break
        desc = desc or rec.get("description", "")
        cves = sorted(set(CVE_RE.findall(json.dumps(rec)))) if adv_id.startswith("PAN-SA") else [adv_id] if CVE_RE.fullmatch(adv_id) else []
        out.append(
            {
                "adv_id": adv_id,
                "title": title,
                "url": f"https://security.paloaltonetworks.com/{adv_id}",
                "published": to_iso(meta.get("datePublished") or cna.get("datePublic") or rec.get("published_date") or rec.get("date")),
                "updated": to_iso(meta.get("dateUpdated") or rec.get("last_modified_date") or rec.get("updated")),
                "severity": sev,
                "cvss": cv["score"] if cv else None,
                "cvss_version": cv["version"] if cv else "",
                "cvss_vector": cv["vector"] if cv else "",
                "cves": cves,
                "summary": strip_tags(desc)[:1000],
            }
        )
    return out


def parse_rss(raw: bytes, src: dict) -> list[dict]:
    """RSS 2.0 / RSS 1.0(RDF) / Atom を汎用的に読む"""
    root = ET.fromstring(raw)

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    items = [e for e in root.iter() if local(e.tag) in ("item", "entry")]
    id_re = re.compile(src["id_regex"]) if src.get("id_regex") else None
    out = []
    for it in items:
        f: dict[str, str] = {}
        for c in it:
            name = local(c.tag)
            if name == "link" and c.get("href"):
                f.setdefault("link", c.get("href"))
            elif c.text and name not in f:
                f[name] = c.text
        title = strip_tags(f.get("title", ""))
        link = (f.get("link") or f.get("guid") or f.get("id") or "").strip()
        desc_raw = f.get("description") or f.get("summary") or f.get("content") or f.get("encoded") or ""
        desc = strip_tags(desc_raw)
        blob = f"{title} {desc} {link}"
        adv_id = ""
        if id_re:
            m = id_re.search(blob)
            adv_id = m.group(0) if m else ""
        if not adv_id:
            adv_id = (f.get("guid") or link or hashlib.sha1(title.encode()).hexdigest()[:16]).strip()
        sev = ""
        m = re.search(r"Severity[:\s]*\(?\s*(Critical|High|Medium|Moderate|Low|Informational)", blob, re.I)
        if m:
            sev = norm_sev(m.group(1))
        m = re.search(r"Security Impact Rating[:\s]*(Critical|High|Medium|Low|Informational)", blob, re.I)
        if m:
            sev = norm_sev(m.group(1))
        score = None
        m = re.search(r"CVSS\s*(?:v\d(?:\.\d)?)?[^0-9]{0,30}?(?:Score|base)[^0-9]{0,10}(\d{1,2}\.\d)", blob, re.I)
        if m:
            score = float(m.group(1))
        out.append(
            {
                "adv_id": adv_id,
                "title": title or adv_id,
                "url": link,
                "published": to_iso(f.get("pubDate") or f.get("published") or f.get("date") or f.get("issued")),
                "updated": to_iso(f.get("updated") or f.get("modified") or ""),
                "severity": sev or sev_from_score(score),
                "cvss": score,
                "cvss_version": "",
                "cvss_vector": "",
                "cves": sorted(set(CVE_RE.findall(blob))),
                "summary": desc[:1000],
            }
        )
    return out


def parse_html_list(raw: bytes, src: dict) -> list[dict]:
    """RSSのないベンダー向け: 一覧ページのリンクからアドバイザリを拾う"""
    text = raw.decode("utf-8", "replace")
    link_re = re.compile(src.get("link_regex", r"advisor"), re.I)
    id_re = re.compile(src["id_regex"], re.I)
    fmt = src.get("id_format", "{0}")
    seen, out = set(), []
    for m in re.finditer(r"<a\s[^>]*?href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", text, re.I | re.S):
        href, inner = html.unescape(m.group(1)), strip_tags(m.group(2))
        if not link_re.search(href):
            continue
        mid = id_re.search(inner) or id_re.search(href)
        if not mid:
            continue
        key = mid.group(1) if mid.groups() else mid.group(0)
        adv_id = fmt.format(key)
        good_title = bool(id_re.search(inner)) or len(inner) > 15
        if adv_id in seen:
            prev = next(o for o in out if o["adv_id"] == adv_id)
            if good_title and not prev["_good"]:
                prev["title"], prev["_good"] = inner, True
            continue
        seen.add(adv_id)
        out.append({
            "_good": good_title,
            "adv_id": adv_id,
            "title": inner if len(inner) > 3 else adv_id,
            "url": urllib.parse.urljoin(src["url"], href),
            "published": "", "updated": "", "severity": "", "cvss": None,
            "cvss_version": "", "cvss_vector": "", "cves": [], "summary": "",
        })
    for o in out:
        o.pop("_good", None)
    if not out:
        raise ValueError("一覧ページからアドバイザリを見つけられませんでした（ページ構成が変わった可能性）")
    return out


PARSERS = {"paloalto_json": parse_paloalto_json, "rss": parse_rss, "html_list": parse_html_list}


# ----------------------------------------------------------------------------
# 補完: アドバイザリページ / NVD / CISA KEV
# ----------------------------------------------------------------------------
PAGE_SCORE_RES = [
    re.compile(r"CVSS\s*v?3(?:\.\d)?\s*(?:Base\s*)?Score\s*[:：]?\s*(\d{1,2}\.\d)", re.I),
    re.compile(r"CVSS\s*Score\s*[:：]?\s*(?:Base\s*)?(\d{1,2}\.\d)", re.I),
    re.compile(r"Base\s*Score\s*[:：]?\s*(\d{1,2}\.\d)", re.I),
]


DATE_RE = re.compile(r"(January|February|March|April|May|June|July|August|September|October|November|December)"
                     r"\s+\d{1,2},\s+\d{4}")


def scrape_page(url: str) -> tuple[list[str], float | None, str]:
    text = strip_tags(http_get(url, timeout=20).decode("utf-8", "replace"))
    date = ""
    m = DATE_RE.search(text)
    if m:
        try:
            date = dt.datetime.strptime(re.sub(r"\s+", " ", m.group(0)), "%B %d, %Y").strftime("%Y-%m-%dT00:00:00Z")
        except ValueError:
            pass
    cves = sorted(set(CVE_RE.findall(text)))
    score = None
    for r in PAGE_SCORE_RES:
        m = r.search(text)
        if m:
            v = float(m.group(1))
            if 0 <= v <= 10:
                score = v
                break
    return cves, score, date


class NVD:
    def __init__(self, con: sqlite3.Connection, cfg: dict):
        self.con = con
        self.key = cfg.get("api_key") or os.environ.get("NVD_API_KEY", "")
        self.wait = 0.7 if self.key else 6.5  # 50/30s, 5/30s
        self.budget = int(cfg.get("max_lookups_per_run", 40))
        self.cache_days = int(cfg.get("cache_days", 7))
        self._last = 0.0

    def lookup(self, cve: str) -> dict | None:
        row = self.con.execute("SELECT * FROM cve_cache WHERE cve=?", (cve,)).fetchone()
        if row:
            if row["cvss"] is not None:
                return dict(row)
            age = utcnow() - dt.datetime.fromisoformat(row["fetched"])
            if age.days < self.cache_days:  # NVD未採点のものは数日おきに再確認
                return None
        if self.budget <= 0:
            return None
        self.budget -= 1
        sleep = self.wait - (time.time() - self._last)
        if sleep > 0:
            time.sleep(sleep)
        self._last = time.time()
        hdr = {"apiKey": self.key} if self.key else {}
        try:
            data = json.loads(http_get(f"{NVD_URL}?cveId={cve}", headers=hdr))
        except Exception as e:  # noqa: BLE001
            log(f"  NVD取得失敗 {cve}: {e}")
            return None
        score = ver = vec = None
        vulns = data.get("vulnerabilities") or []
        if vulns:
            metrics = vulns[0].get("cve", {}).get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    prim = next((m for m in arr if m.get("type") == "Primary"), arr[0])
                    cd = prim.get("cvssData", {})
                    score, ver, vec = cd.get("baseScore"), cd.get("version"), cd.get("vectorString")
                    break
        self.con.execute(
            "INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?,?)",
            (cve, score, ver, vec, utcnow().isoformat()),
        )
        self.con.commit()
        return {"cvss": score, "version": ver, "vector": vec} if score is not None else None


def refresh_kev(con: sqlite3.Connection) -> int:
    data = json.loads(http_get(KEV_URL, timeout=60))
    rows = [
        (v["cveID"], v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", ""),
         v.get("vulnerabilityName", ""))
        for v in data.get("vulnerabilities", [])
    ]
    con.execute("DELETE FROM kev")
    con.executemany("INSERT OR REPLACE INTO kev VALUES (?,?,?,?)", rows)
    con.commit()
    return len(rows)


# ----------------------------------------------------------------------------
# 通知
# ----------------------------------------------------------------------------
def matches_rule(a: dict, rule: dict) -> bool:
    vendors = rule.get("vendors") or []
    if vendors and a["vendor"] not in vendors:
        return False
    if rule.get("kev_always", True) and a["kev"]:
        return True
    hay = f"{a['title']} {a['summary']}".lower()
    kws = [k.lower() for k in rule.get("keywords") or []]
    if kws and not any(k in hay for k in kws):
        return False
    excl = [k.lower() for k in rule.get("exclude_keywords") or []]
    if any(k in hay for k in excl):
        return False
    sevs = [s.upper() for s in rule.get("severities") or []]
    min_cvss = rule.get("min_cvss")
    if a["cvss"] is None and not a["severity"]:
        return bool(rule.get("notify_unscored", True))  # スコア不明は取りこぼし防止で通知
    if a["cvss"] is not None and min_cvss is not None:
        return a["cvss"] >= float(min_cvss)
    if sevs:
        return (a["severity"] or "").upper() in sevs
    if a["cvss"] is None and rule.get("notify_unscored", True):
        return True
    return min_cvss is None


def fmt_line(a: dict) -> str:
    score = f"CVSS {a['cvss']:.1f}" + (f" (v{a['cvss_version']})" if a["cvss_version"] else "") if a["cvss"] is not None else "CVSS -"
    kev = " 🚨KEV(悪用確認済)" if a["kev"] else ""
    return f"[{a['vendor']}] {a['severity'] or '-'} / {score}{kev}\n{a['adv_id']} {a['title']}\n{a['url']}"


def send_notifications(cfg: dict, items: list[dict], header: str) -> None:
    if not items:
        return
    n = cfg.get("notify", {})
    lines = [fmt_line(a) for a in items]
    text = f"{header}（{len(items)}件）\n\n" + "\n\n".join(lines)
    chunks = []
    cur = ""
    for ln in [f"{header}（{len(items)}件）"] + lines:  # Slack/Discord の文字数制限対策
        if len(cur) + len(ln) + 2 > 1800:
            chunks.append(cur)
            cur = ""
        cur += ln + "\n\n"
    if cur:
        chunks.append(cur)

    for url in _as_list(n.get("slack_webhook")):
        for c in chunks:
            _try(lambda: http_post_json(url, {"text": c}), "Slack")
    for url in _as_list(n.get("discord_webhook")):
        for c in chunks:
            _try(lambda: http_post_json(url, {"content": c}), "Discord")
    for url in _as_list(n.get("generic_webhook")):
        _try(lambda: http_post_json(url, {"text": text, "items": items}), "Webhook")
    nt = n.get("ntfy") or {}
    if nt.get("topic"):
        for a in items:
            _try(lambda a=a: _send_ntfy(nt, a, header), "ntfy")
    em = n.get("email") or {}
    if em.get("enabled"):
        _try(lambda: _send_mail(em, header, text), "Email")
    if not any([n.get("slack_webhook"), n.get("discord_webhook"), n.get("generic_webhook"),
                em.get("enabled"), nt.get("topic")]):
        print("\n" + text + "\n")


def _as_list(v):
    if not v:
        return []
    return v if isinstance(v, list) else [v]


def _try(fn, name):
    try:
        fn()
        log(f"  通知送信OK: {name}")
    except Exception as e:  # noqa: BLE001
        log(f"  通知送信失敗: {name}: {e}")


def _send_ntfy(nt: dict, a: dict, header: str) -> None:
    """ntfy (Android/iOSアプリ) へプッシュ通知。1件ずつ送り、タップで原文を開く"""
    score = a["cvss"] or 0
    prio = 5 if (a["kev"] or score >= 9) else 4 if score >= 7 else 3
    tags = ["rotating_light"] if a["kev"] else ["warning"] if score >= 7 else ["information_source"]
    sc = f"CVSS {score:.1f}" if a["cvss"] is not None else "CVSS -"
    body = {
        "topic": nt["topic"],
        "title": f"[{a['vendor']}] {sc}{' KEV' if a['kev'] else ''} {a['severity'] or ''}".strip(),
        "message": f"{a['adv_id']} {a['title']}",
        "priority": prio,
        "tags": tags,
        "click": a["url"],
    }
    if nt.get("app_url"):
        body["actions"] = [{"action": "view", "label": "secwatchで開く", "url": nt["app_url"]}]
    data = json.dumps(body).encode("utf-8")
    hdr = {"Content-Type": "application/json", "User-Agent": UA}
    if nt.get("token"):
        hdr["Authorization"] = f"Bearer {nt['token']}"
    req = urllib.request.Request(nt.get("server", "https://ntfy.sh").rstrip("/") + "/", data=data, headers=hdr)
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def _send_mail(em: dict, subject: str, body: str) -> None:
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[secwatch] {subject}"
    msg["From"] = em["from"]
    msg["To"] = ", ".join(_as_list(em["to"]))
    port = int(em.get("port", 587))
    if port == 465:
        s = smtplib.SMTP_SSL(em["host"], port, timeout=20)
    else:
        s = smtplib.SMTP(em["host"], port, timeout=20)
        if em.get("starttls", True):
            s.starttls()
    if em.get("user"):
        s.login(em["user"], em.get("password") or os.environ.get("SECWATCH_SMTP_PASSWORD", ""))
    s.sendmail(em["from"], _as_list(em["to"]), msg.as_string())
    s.quit()


# ----------------------------------------------------------------------------
# fetch 本体
# ----------------------------------------------------------------------------
def upsert(con: sqlite3.Connection, vendor: str, it: dict) -> tuple[str, bool, bool]:
    uid = f"{vendor}:{it['adv_id']}"
    now = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    h = hashlib.sha1(json.dumps([it["title"], it["updated"], it["cvss"], it["severity"], it["cves"]],
                                sort_keys=True).encode()).hexdigest()
    row = con.execute("SELECT * FROM advisories WHERE uid=?", (uid,)).fetchone()
    cves = ",".join(it["cves"])
    if row is None:
        con.execute(
            """INSERT INTO advisories (uid,vendor,adv_id,title,url,published,updated,severity,cvss,
               cvss_version,cvss_vector,cvss_source,cves,summary,content_hash,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, vendor, it["adv_id"], it["title"], it["url"], it["published"], it["updated"],
             it["severity"], it["cvss"], it["cvss_version"], it["cvss_vector"],
             "vendor" if it["cvss"] is not None else "", cves, it["summary"], h, now, now),
        )
        return uid, True, False
    changed = row["content_hash"] != h
    if changed:
        # ベンダー値で更新（NVD/ページ補完済みの値はベンダー値がない場合は保持）
        cvss = it["cvss"] if it["cvss"] is not None else row["cvss"]
        con.execute(
            """UPDATE advisories SET title=?,url=?,updated=?,severity=COALESCE(NULLIF(?,''),severity),
               cvss=?,cvss_version=CASE WHEN ? IS NOT NULL THEN ? ELSE cvss_version END,
               cvss_vector=CASE WHEN ? IS NOT NULL THEN ? ELSE cvss_vector END,
               cvss_source=CASE WHEN ? IS NOT NULL THEN 'vendor' ELSE cvss_source END,
               cves=CASE WHEN ?<>'' THEN ? ELSE cves END,summary=?,content_hash=?,last_seen=? WHERE uid=?""",
            (it["title"], it["url"], it["updated"], it["severity"], cvss,
             it["cvss"], it["cvss_version"], it["cvss"], it["cvss_vector"], it["cvss"],
             cves, cves, it["summary"], h, now, uid),
        )
    else:
        con.execute("UPDATE advisories SET last_seen=? WHERE uid=?", (now, uid))
    return uid, False, changed


def cmd_fetch(cfg: dict, args) -> int:
    con = db_connect(cfg["db_path"])
    first_run = con.execute("SELECT COUNT(*) FROM advisories").fetchone()[0] == 0
    touched: set[str] = set()
    errors = 0

    # 1) ソースごとに収集
    for src in cfg["sources"]:
        if not src.get("enabled", True):
            continue
        vendor = src["vendor"]
        attempts = [src] + [dict(src, **fb) for fb in _as_list(src.get("fallback"))]
        items, err = None, ""
        for a in attempts:
            try:
                raw = http_get(a["url"], timeout=int(a.get("timeout", 45)))
                items = PARSERS[a["type"]](raw, a)
                if a is not src:
                    log(f"[{vendor}] フォールバック {a['url']} を使用")
                break
            except Exception as e:  # noqa: BLE001
                err = f"{a['url']}: {e}"
                log(f"[{vendor}] 取得失敗 {err}")
        if items is None:
            errors += 1
            con.execute("INSERT INTO runs (at,source,ok,items,new,message) VALUES (?,?,?,?,?,?)",
                        (utcnow().isoformat(), vendor, 0, 0, 0, err[:500]))
            continue
        new = 0
        for it in items:
            uid, is_new, _ = upsert(con, vendor, it)
            touched.add(uid)
            new += is_new
        con.execute("INSERT INTO runs (at,source,ok,items,new,message) VALUES (?,?,?,?,?,?)",
                    (utcnow().isoformat(), vendor, 1, len(items), new, ""))
        con.commit()
        log(f"[{vendor}] {len(items)}件取得 / 新規 {new}件")

    # 2) ページ取得で CVE / CVSS を補完（新しいものから、上限あり）
    src_by_vendor = {s["vendor"]: s for s in cfg["sources"]}
    page_budget = int(cfg.get("scrape_max_per_run", 40))
    rows = con.execute(
        "SELECT * FROM advisories WHERE scraped=0 AND (cvss IS NULL OR cves='' OR published='') ORDER BY first_seen DESC, published DESC"
    ).fetchall()
    for r in rows:
        s = src_by_vendor.get(r["vendor"], {})
        if not s.get("scrape_page") or page_budget <= 0 or not r["url"].startswith("http"):
            continue
        page_budget -= 1
        try:
            cves, score, date = scrape_page(r["url"])
            con.execute(
                """UPDATE advisories SET scraped=1,
                   cves=CASE WHEN cves='' THEN ? ELSE cves END,
                   cvss=COALESCE(cvss, ?),
                   cvss_source=CASE WHEN cvss IS NULL AND ? IS NOT NULL THEN 'page' ELSE cvss_source END,
                   severity=CASE WHEN severity='' THEN ? ELSE severity END,
                   published=CASE WHEN published='' THEN ? ELSE published END
                   WHERE uid=?""",
                (",".join(cves), score, score, sev_from_score(score), date, r["uid"]),
            )
            con.commit()
            time.sleep(1.0)
        except Exception as e:  # noqa: BLE001
            log(f"  ページ取得失敗 {r['url']}: {e}")
            con.execute("UPDATE advisories SET scraped=1 WHERE uid=?", (r["uid"],))

    # 3) NVD で CVSS 補完
    nvd_cfg = cfg.get("nvd", {})
    if nvd_cfg.get("enabled", True):
        nvd = NVD(con, nvd_cfg)
        rows = con.execute(
            "SELECT uid,cves FROM advisories WHERE cvss IS NULL AND cves<>'' ORDER BY published DESC LIMIT 200"
        ).fetchall()
        for r in rows:
            best = None
            for cve in r["cves"].split(",")[:10]:
                res = nvd.lookup(cve)
                if res and (best is None or res["cvss"] > best["cvss"]):
                    best = res
            if best:
                con.execute(
                    """UPDATE advisories SET cvss=?,cvss_version=?,cvss_vector=?,cvss_source='nvd',
                       severity=CASE WHEN severity='' THEN ? ELSE severity END WHERE uid=?""",
                    (best["cvss"], best["version"] or "", best["vector"] or "",
                     sev_from_score(best["cvss"]), r["uid"]),
                )
                con.commit()

    # 4) CISA KEV 照合
    if cfg.get("kev", {}).get("enabled", True):
        try:
            n = refresh_kev(con)
            log(f"[KEV] {n}件読み込み")
        except Exception as e:  # noqa: BLE001
            log(f"[KEV] 取得失敗: {e}")
        kevs = {r[0] for r in con.execute("SELECT cve FROM kev")}
        for r in con.execute("SELECT uid,cves FROM advisories WHERE kev=0 AND cves<>''").fetchall():
            if set(r["cves"].split(",")) & kevs:
                con.execute("UPDATE advisories SET kev=1 WHERE uid=?", (r["uid"],))
        con.commit()

    # 5) 通知
    rule = cfg.get("notify", {}).get("rule", {})
    max_age = int(cfg.get("notify", {}).get("max_age_days", 30))
    cutoff = (utcnow() - dt.timedelta(days=max_age)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = [dict(r) for r in con.execute("SELECT * FROM advisories WHERE notified=0")]
    to_notify = [a for a in rows if (a["published"] or a["first_seen"]) >= cutoff and matches_rule(a, rule)]
    kev_rows = [dict(r) for r in con.execute("SELECT * FROM advisories WHERE kev=1 AND notified_kev=0 AND notified=1")]

    silent = (first_run and not args.notify_initial) or args.no_notify
    if silent:
        log(f"初回実行のため通知はスキップ（対象 {len(to_notify)}件）。--notify-initial で送信できます")
    else:
        send_notifications(cfg, sorted(to_notify, key=lambda a: -(a["cvss"] or 0)), "新しいセキュリティアドバイザリ")
        send_notifications(cfg, kev_rows, "🚨 CISA KEV に追加（実際の悪用を確認）")
    con.execute("UPDATE advisories SET notified=1 WHERE notified=0")
    con.execute("UPDATE advisories SET notified_kev=1 WHERE kev=1")
    con.commit()
    log(f"完了: 通知 {0 if silent else len(to_notify) + len(kev_rows)}件 / エラー {errors}ソース")
    return 1 if errors and errors == len([s for s in cfg['sources'] if s.get('enabled', True)]) else 0


# ----------------------------------------------------------------------------
# list
# ----------------------------------------------------------------------------
def cmd_list(cfg: dict, args) -> int:
    con = db_connect(cfg["db_path"])
    q = "SELECT * FROM advisories WHERE 1=1"
    p: list = []
    if args.min is not None:
        q += " AND cvss>=?"
        p.append(args.min)
    if args.vendor:
        q += " AND vendor=?"
        p.append(args.vendor)
    q += " ORDER BY published DESC LIMIT ?"
    p.append(args.limit)
    for r in con.execute(q, p):
        sc = f"{r['cvss']:.1f}" if r["cvss"] is not None else " - "
        print(f"{(r['published'] or '')[:10]}  {r['vendor']:<10} {sc:>4} {r['severity'] or '-':<9} "
              f"{'KEV ' if r['kev'] else ''}{r['adv_id']}  {r['title'][:70]}  [{r['status']}]")
    return 0


# ----------------------------------------------------------------------------
# Web UI
# ----------------------------------------------------------------------------
CSS = """
:root{--bg:#f6f7f9;--fg:#1d2330;--mut:#667085;--line:#e3e6eb;--card:#fff;--crit:#b42318;--high:#d9480f;
--med:#b08800;--low:#2f6f4f;--kev:#7a1fa2}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--fg:#e6e8ec;--mut:#98a2b3;--line:#2a2f3a;--card:#1a1e26}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;
background:var(--bg);color:var(--fg)}header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
gap:16px;align-items:baseline;flex-wrap:wrap}h1{font-size:18px;margin:0}.mut{color:var(--mut)}
main{padding:16px 20px;max-width:1400px}form.f{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
select,input,button,textarea{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--card);color:var(--fg)}button{cursor:pointer}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}.st{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:8px 14px}.st b{font-size:20px;display:block}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--mut);font-weight:600;white-space:nowrap}td.n{font-variant-numeric:tabular-nums;white-space:nowrap}
.sev{font-weight:700;font-size:12px}.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}
.kev{background:var(--kev);color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:700}
a{color:inherit}td.t a{font-weight:600;text-decoration:none}td.t a:hover{text-decoration:underline}
.sm{font-size:12px}details summary{cursor:pointer;color:var(--mut);font-size:12px}
.upd select{padding:3px 6px}.upd input{width:140px;padding:3px 6px}.err{color:var(--crit)}
"""


def render_page(con: sqlite3.Connection, qs: dict) -> str:
    g = lambda k, d="": qs.get(k, [d])[0]  # noqa: E731
    vendor, status, minc, kw, kev = g("vendor"), g("status"), g("min"), g("q"), g("kev")
    days = g("days", "90")
    q = "SELECT * FROM advisories WHERE 1=1"
    p: list = []
    if vendor:
        q += " AND vendor=?"; p.append(vendor)
    if status:
        q += " AND status=?"; p.append(status)
    if minc:
        try:
            q += " AND cvss>=?"; p.append(float(minc))
        except ValueError:
            pass
    if kw:
        q += " AND (title LIKE ? OR summary LIKE ? OR cves LIKE ? OR adv_id LIKE ? OR memo LIKE ?)"
        p += [f"%{kw}%"] * 5
    if kev:
        q += " AND kev=1"
    if days and days != "all":
        cutoff = (utcnow() - dt.timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%SZ")
        q += " AND COALESCE(NULLIF(published,''),first_seen)>=?"; p.append(cutoff)
    q += " ORDER BY COALESCE(NULLIF(published,''),first_seen) DESC LIMIT 500"
    rows = con.execute(q, p).fetchall()

    vendors = [r[0] for r in con.execute("SELECT DISTINCT vendor FROM advisories ORDER BY vendor")]
    tot = con.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
    open_hi = con.execute("SELECT COUNT(*) FROM advisories WHERE cvss>=7 AND status IN ('未確認','確認中','対応中')").fetchone()[0]
    kev_open = con.execute("SELECT COUNT(*) FROM advisories WHERE kev=1 AND status IN ('未確認','確認中','対応中')").fetchone()[0]
    unseen = con.execute("SELECT COUNT(*) FROM advisories WHERE status='未確認'").fetchone()[0]
    last = con.execute("SELECT source,ok,at,message FROM runs WHERE id IN (SELECT MAX(id) FROM runs GROUP BY source)").fetchall()

    e = html.escape
    opt = lambda vals, cur, blank: f'<option value="">{blank}</option>' + "".join(  # noqa: E731
        f'<option value="{e(v)}"{" selected" if v == cur else ""}>{e(v)}</option>' for v in vals)
    run_info = " / ".join(
        f'{e(r["source"])} {"✓" if r["ok"] else "<span class=err>✗</span>"} {e(r["at"][:16].replace("T", " "))}'
        for r in last)

    out = [f"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>secwatch</title><style>{CSS}</style></head><body>
<header><h1>secwatch</h1><span class="mut sm">最終取得(UTC): {run_info or 'まだ取得していません'}</span></header><main>
<div class="stats"><div class="st"><b>{tot}</b><span class="mut sm">総件数</span></div>
<div class="st"><b>{unseen}</b><span class="mut sm">未確認</span></div>
<div class="st"><b class="HIGH">{open_hi}</b><span class="mut sm">CVSS7以上・未完了</span></div>
<div class="st"><b style="color:var(--kev)">{kev_open}</b><span class="mut sm">KEV・未完了</span></div></div>
<form class="f" method="get">
<select name="vendor">{opt(vendors, vendor, 'ベンダー: すべて')}</select>
<select name="status">{opt(STATUSES, status, '状態: すべて')}</select>
<select name="min">{opt(['9.0', '7.0', '4.0'], minc, 'CVSS: すべて')}</select>
<select name="days">{''.join(f'<option value="{v}"{" selected" if v == days else ""}>{l}</option>' for v, l in [('7', '7日'), ('30', '30日'), ('90', '90日'), ('365', '1年'), ('all', '全期間')])}</select>
<label class="sm"><input type="checkbox" name="kev" value="1"{" checked" if kev else ""}> KEVのみ</label>
<input name="q" value="{e(kw)}" placeholder="キーワード / CVE / メモ">
<button>絞り込み</button></form>
<table><thead><tr><th>公開日</th><th>ベンダー</th><th>CVSS</th><th>深刻度</th><th>タイトル</th><th>状態・メモ</th></tr></thead><tbody>"""]
    for r in rows:
        sc = f"{r['cvss']:.1f}" if r["cvss"] is not None else "-"
        src = {"nvd": "NVD", "page": "ページ", "vendor": ""}.get(r["cvss_source"] or "", "")
        ver = f"v{r['cvss_version']}" if r["cvss_version"] else ""
        meta = " ".join(x for x in [ver, src] if x)
        sev = r["severity"] or sev_from_score(r["cvss"])
        cves = ", ".join(r["cves"].split(",")[:6]) if r["cves"] else ""
        sel = "".join(f'<option{" selected" if s == r["status"] else ""}>{s}</option>' for s in STATUSES)
        out.append(f"""<tr><td class="n sm">{e((r['published'] or r['first_seen'] or '')[:10])}</td>
<td class="sm">{e(r['vendor'])}</td>
<td class="n"><b class="{e(sev)}">{sc}</b><div class="mut sm">{e(meta)}</div></td>
<td><span class="sev {e(sev)}">{e(sev or '-')}</span>{' <span class="kev">KEV</span>' if r['kev'] else ''}</td>
<td class="t"><a href="{e(r['url'])}" target="_blank" rel="noopener">{e(r['adv_id'])} {e(r['title'])}</a>
<div class="mut sm">{e(cves)}</div>{f'<details><summary>概要</summary><div class="sm">{e(r["summary"])}</div></details>' if r['summary'] else ''}</td>
<td><form class="upd" method="post" action="/update"><input type="hidden" name="uid" value="{e(r['uid'])}">
<select name="status" onchange="this.form.submit()">{sel}</select>
<input name="memo" value="{e(r['memo'] or '')}" placeholder="メモ" onchange="this.form.submit()"></form></td></tr>""")
    if not rows:
        out.append('<tr><td colspan="6" class="mut">該当なし</td></tr>')
    out.append(f'</tbody></table><p class="mut sm">{len(rows)}件表示（最大500件）</p></main></body></html>')
    return "".join(out)


STATIC_DIR = os.path.join(BASE_DIR, "static")
PUBLIC_PATHS = {"/manifest.webmanifest", "/icon-192.png", "/icon-512.png", "/sw.js"}


def make_icon_png(size: int) -> bytes:
    """標準ライブラリだけでアプリアイコン(PNG)を描く: 紺地にオレンジの盾"""
    import struct
    import zlib
    bg, fg, hi = (29, 35, 48), (249, 115, 22), (255, 255, 255)
    rows = []
    for py in range(size):
        row = bytearray([0])
        y = (py + 0.5) / size * 2 - 1
        for px in range(size):
            x = (px + 0.5) / size * 2 - 1
            c = bg
            inside = (abs(x) < 0.42 and -0.5 < y <= 0.08) or (0.08 < y < 0.6 and abs(x) < 0.42 * (0.6 - y) / 0.52)
            if inside:
                c = fg
                if abs(x) < 0.06 and -0.32 < y < 0.12:  # 「!」の棒
                    c = hi
                if x * x + (y - 0.27) ** 2 < 0.07 ** 2:  # 「!」の点
                    c = hi
            row += bytes(c)
        rows.append(bytes(row))

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")


def make_handler(cfg: dict):
    import base64
    import hmac

    db_path = cfg["db_path"]
    web = cfg.get("web", {})
    user, pw = web.get("username", ""), web.get("password", "") or os.environ.get("SECWATCH_WEB_PASSWORD", "")
    expected = ("Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()) if user and pw else ""
    icons = {"/icon-192.png": make_icon_png(192), "/icon-512.png": make_icon_png(512)}
    static_types = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
                    ".webmanifest": "application/manifest+json; charset=utf-8"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body, ctype="text/html; charset=utf-8", extra=None):
            b = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8",
                       {"Cache-Control": "no-store"})

        def _authed(self, path: str) -> bool:
            if not expected or path in PUBLIC_PATHS:
                return True
            got = self.headers.get("Authorization", "")
            if hmac.compare_digest(got.encode(), expected.encode()):
                return True
            self._send(401, "認証が必要です", "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="secwatch", charset="UTF-8"'})
            return False

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            return urllib.parse.urlparse(origin).netloc == self.headers.get("Host", "")

        def _static(self, name: str):
            fp = os.path.join(STATIC_DIR, name)
            if not os.path.isfile(fp):
                return self._send(404, "not found", "text/plain")
            with open(fp, "rb") as f:
                data = f.read()
            extra = {"Cache-Control": "no-cache"}
            if name == "sw.js":
                extra["Service-Worker-Allowed"] = "/"
            self._send(200, data, static_types.get(os.path.splitext(name)[1], "application/octet-stream"), extra)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            if not self._authed(u.path):
                return
            if u.path in ("/", "/index.html"):
                return self._static("index.html")
            if u.path in ("/sw.js", "/manifest.webmanifest"):
                return self._static(u.path.lstrip("/"))
            if u.path in icons:
                return self._send(200, icons[u.path], "image/png", {"Cache-Control": "max-age=604800"})
            con = db_connect(db_path)
            try:
                if u.path == "/table":
                    self._send(200, render_page(con, urllib.parse.parse_qs(u.query)))
                elif u.path == "/api/advisories":
                    qs = urllib.parse.parse_qs(u.query)
                    days = qs.get("days", ["180"])[0]
                    q, p = "SELECT * FROM advisories", []
                    if days != "all":
                        q += " WHERE COALESCE(NULLIF(published,''),first_seen)>=?"
                        p.append((utcnow() - dt.timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%SZ"))
                    q += " ORDER BY COALESCE(NULLIF(published,''),first_seen) DESC LIMIT 2000"
                    rows = [{k: r[k] for k in r.keys() if k not in ("content_hash",)} for r in con.execute(q, p)]
                    runs = [dict(r) for r in con.execute(
                        "SELECT source,ok,at,items,new,message FROM runs WHERE id IN (SELECT MAX(id) FROM runs GROUP BY source)")]
                    self._json({"advisories": rows, "runs": runs, "statuses": STATUSES,
                                "generated": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")})
                elif u.path == "/export.csv":
                    import csv
                    import io
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    cols = ["vendor", "adv_id", "title", "published", "severity", "cvss", "cvss_version",
                            "cvss_source", "cves", "kev", "status", "memo", "url"]
                    w.writerow(cols)
                    for r in con.execute(f"SELECT {','.join(cols)} FROM advisories ORDER BY published DESC"):
                        w.writerow(list(r))
                    self._send(200, "\ufeff" + buf.getvalue(), "text/csv; charset=utf-8",
                               {"Content-Disposition": "attachment; filename=secwatch.csv"})
                else:
                    self._send(404, "not found", "text/plain")
            finally:
                con.close()

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            if not self._authed(u.path):
                return
            if not self._same_origin():
                return self._send(403, "forbidden", "text/plain")
            n = min(int(self.headers.get("Content-Length", 0)), 100_000)
            body = self.rfile.read(n).decode("utf-8")
            if u.path == "/api/update":
                if not self.headers.get("Content-Type", "").startswith("application/json"):
                    return self._json({"error": "json required"}, 415)
                try:
                    f = json.loads(body)
                except ValueError:
                    return self._json({"error": "bad json"}, 400)
                uid, st, memo = f.get("uid", ""), f.get("status", ""), str(f.get("memo", ""))[:1000]
                if st not in STATUSES or not uid:
                    return self._json({"error": "bad request"}, 400)
                con = db_connect(db_path)
                cur = con.execute("UPDATE advisories SET status=?, memo=? WHERE uid=?", (st, memo, uid))
                con.commit()
                con.close()
                return self._json({"ok": cur.rowcount == 1})
            if u.path == "/update":  # /table 画面のフォーム
                f = urllib.parse.parse_qs(body)
                uid, st = f.get("uid", [""])[0], f.get("status", ["未確認"])[0]
                memo = f.get("memo", [""])[0][:1000]
                if st in STATUSES and uid:
                    con = db_connect(db_path)
                    con.execute("UPDATE advisories SET status=?, memo=? WHERE uid=?", (st, memo, uid))
                    con.commit()
                    con.close()
                self.send_response(303)
                self.send_header("Location", "/table")
                self.end_headers()
                return
            self._send(404, "not found", "text/plain")

    return H, bool(expected)


def cmd_serve(cfg: dict, args) -> int:
    db_connect(cfg["db_path"]).close()
    host = args.host or cfg.get("web", {}).get("host", "127.0.0.1")
    port = args.port or int(cfg.get("web", {}).get("port", 8080))
    handler, auth = make_handler(cfg)
    if host not in ("127.0.0.1", "localhost", "::1") and not auth:
        print("エラー: 127.0.0.1 以外で待ち受けるときは config.json の web.username / web.password を設定してください",
              file=sys.stderr)
        return 2
    srv = ThreadingHTTPServer((host, port), handler)
    log(f"Web画面: http://{host}:{port}/  {'(認証あり)' if auth else ''} (Ctrl+C で終了)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_test_notify(cfg: dict, args) -> int:
    sample = {"vendor": "TEST", "adv_id": "CVE-0000-0000", "title": "secwatch 通知テスト",
              "url": "https://example.com", "severity": "CRITICAL", "cvss": 9.8,
              "cvss_version": "3.1", "kev": 1, "summary": ""}
    send_notifications(cfg, [sample], "通知テスト")
    return 0


# ----------------------------------------------------------------------------
def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    db = cfg.get("db_path", "secwatch.db")
    cfg["db_path"] = db if os.path.isabs(db) else os.path.join(os.path.dirname(os.path.abspath(path)), db)
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description="ベンダーセキュリティアドバイザリ収集・通知")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch", help="収集して通知")
    p.add_argument("--no-notify", action="store_true", help="通知しない（既読扱いにする）")
    p.add_argument("--notify-initial", action="store_true", help="初回実行でも通知する")
    p = sub.add_parser("serve", help="Web画面を起動")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p = sub.add_parser("list", help="一覧表示")
    p.add_argument("--min", type=float)
    p.add_argument("--vendor")
    p.add_argument("--limit", type=int, default=50)
    sub.add_parser("test-notify", help="通知テスト")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        print(f"設定ファイルがありません: {args.config}\nconfig.example.json を config.json にコピーしてください", file=sys.stderr)
        return 2
    cfg = load_config(args.config)
    return {"fetch": cmd_fetch, "serve": cmd_serve, "list": cmd_list, "test-notify": cmd_test_notify}[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
