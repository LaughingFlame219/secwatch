#!/usr/bin/env python3
"""
fwwatch - ファームウェアの新バージョンとサポート終了（EOL）を監視して通知する

  取得元
    endoflife.date : PAN-OS / GlobalProtect / FortiOS / Cisco IOS XE（リリース系列ごとの最新版・EOL日）
    Juniper 公式    : Junos OS Dates & Milestones（FRS / End of Engineering / End of Support）
    Arista 公式     : End of Software Support の RSS（EOS 系列のサポート終了日）
    Fortinet 公式   : ファームウェア更新の RSS（新バージョンの公開）

  通知（ntfy）
    ・使っている系列（MY_TRAINS）に新しいバージョンが出たとき
    ・新しいリリース系列が出たとき（例: PAN-OS 12.3）
    ・サポート終了まで 180 / 90 / 30 / 7 / 0 日になったとき

環境変数
  MY_TRAINS        使っている系列。例: panos:11.1,fortios:7.4,cisco-ios-xe:17.12,junos:23.4,arista-eos:4.33
                   （空なら、サポート中のすべての系列が対象）
  NOTIFY_RELEASES  mine（既定）/ all / none
  NOTIFY_EOL       mine（既定）/ all / none
  NTFY_TOPIC / NTFY_SERVER / NTFY_TOKEN / APP_URL  … secwatch と共通
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "collector"))
import secwatch_lib as lib  # noqa: E402  （secwatch の取得・RSS解析を流用）
import discord  # noqa: E402

CONFIG = os.path.join(ROOT, "collector_fw", "config.json")
STATE = os.path.join(ROOT, "state_fw", "state.json")
OUT = os.path.join(ROOT, "docs", "fw", "data", "fw.json")
VENDOR_NAME = {"PaloAlto": "Palo Alto", "Fortinet": "Fortinet", "Cisco": "Cisco", "Arista": "Arista", "Juniper": "Juniper"}
log = lib.log


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def today() -> dt.date:
    if env("FW_TODAY"):  # テスト用
        return dt.date.fromisoformat(env("FW_TODAY"))
    return lib.utcnow().date()


def now_iso() -> str:
    return lib.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def d_iso(s) -> str:
    """いろいろな日付表記を YYYY-MM-DD に"""
    if not s or s is True or s is False:
        return ""
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%B %d, %Y", "%b %d, %Y", "%d-%B-%Y", "%d-%b-%Y", "%d %B %Y"):
        try:
            return dt.datetime.strptime(re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", s), fmt).date().isoformat()
        except ValueError:
            pass
    iso = lib.to_iso(s)
    return iso[:10] if re.match(r"\d{4}-\d{2}-\d{2}", iso) else ""


def vkey(v: str) -> tuple:
    """バージョン比較用（11.1.16-h5 → (11,1,16,5)）"""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


# ----------------------------------------------------------------------------
# 取得元ごとのパーサ。どれも trains（リリース系列）のリストを返す:
#   train, released, eoas(エンジニアリング/アクティブサポート終了), eol(サポート終了),
#   latest, latestDate, latestLink, lts, type, maintained
# ----------------------------------------------------------------------------
def fetch_eol_date(p: dict) -> list[dict]:
    slug = p["slug"]
    base = env("EOLDATE_BASE", "https://endoflife.date").rstrip("/")
    try:
        data = json.loads(lib.http_get(f"{base}/api/v1/products/{slug}/", headers={"Accept": "application/json"}))
        rels = data["result"]["releases"]
        out = []
        for r in rels:
            latest = r.get("latest") or {}
            out.append({
                "train": str(r.get("name")), "label": str(r.get("label") or r.get("name")),
                "released": d_iso(r.get("releaseDate")),
                "eoas": d_iso(r.get("eoasFrom")), "eoes": d_iso(r.get("eoesFrom")), "eol": d_iso(r.get("eolFrom")),
                "latest": latest.get("name") or "", "latestDate": d_iso(latest.get("date")), "latestLink": latest.get("link") or "",
                "lts": bool(r.get("isLts")), "type": "LTS" if r.get("isLts") else "",
                "maintained": r.get("isMaintained"),
            })
        return out
    except Exception as e:  # noqa: BLE001  v1 が使えないときは v0 を試す
        log(f"  [{slug}] v1 API 失敗（{e}）。v0 API を試します")
    data = json.loads(lib.http_get(f"{base}/api/{slug}.json"))
    out = []
    for r in data:
        out.append({
            "train": str(r.get("cycle")), "label": str(r.get("cycle")), "released": d_iso(r.get("releaseDate")),
            "eoas": d_iso(r.get("support")), "eoes": d_iso(r.get("extendedSupport")), "eol": d_iso(r.get("eol")),
            "latest": str(r.get("latest") or ""), "latestDate": d_iso(r.get("latestReleaseDate")), "latestLink": r.get("link") or "",
            "lts": bool(r.get("lts")), "type": "LTS" if r.get("lts") else "", "maintained": None,
        })
    return out


def fetch_juniper(p: dict) -> list[dict]:
    html_text = lib.http_get(p["url"], timeout=40).decode("utf-8", "replace")
    out = []
    for row in re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", html_text):
        cells = [lib.strip_tags(c) for c in re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", row)]
        if len(cells) < 4:
            continue
        m = re.match(r"Junos(?:\s+OS)?\s+(\d+\.\d+)", cells[0])
        if not m:
            continue
        out.append({
            "train": m.group(1), "label": m.group(1), "released": d_iso(cells[1]),
            "eoas": d_iso(cells[2]), "eoes": "", "eol": d_iso(cells[3]),
            "latest": "", "latestDate": "", "latestLink": "", "lts": False,
            "type": cells[4].strip() if len(cells) > 4 else "", "maintained": None,
        })
    if not out:
        raise ValueError("Junos の表を読み取れませんでした（ページ構成が変わった可能性）")
    return out


ARISTA_EOL_RES = [
    re.compile(r"End of Support Date:\s*(\d{1,2}-[A-Za-z]+-\d{4})"),
    re.compile(r"(?:timeline|considered End of Support|support)\s+on\s+([A-Z][a-z]+\s+\d{1,2}(?:st|nd|rd|th)?,\s+\d{4})"),
    re.compile(r"until\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})"),
]


def fetch_arista(p: dict) -> list[dict]:
    # 公式のサポート表は画像でしか公開されていないため、書き起こした基準データを土台にする
    out = {}
    for b in p.get("baseline", []):
        out[b["train"]] = {"train": b["train"], "label": b["train"], "released": b.get("released", ""), "eoas": "",
                           "eoes": "", "eol": b.get("eol", ""), "latest": "", "latestDate": "",
                           "latestLink": p.get("link", ""), "lts": False, "type": b.get("type", ""),
                           "note": b.get("note", ""), "maintained": None}
    try:
        items = lib.parse_rss(lib.http_get(p["url"], timeout=40), {"vendor": "Arista"})
    except Exception:  # noqa: BLE001  RSS が取れなくても基準データは出す
        if out:
            return list(out.values())
        raise
    for it in items:
        m = re.search(r"\bEOS[\s-]+(4\.\d+)", it["title"])
        if not m:
            continue
        text = f"{it['title']} {it['summary']}"
        eol = ""
        for r in ARISTA_EOL_RES:
            mm = r.search(text)
            if mm:
                eol = d_iso(mm.group(1))
                if eol:
                    break
        rel = ""
        mm = re.search(r"Release Date:\s*(\d{1,2}-[A-Za-z]+-\d{4})", text)
        if mm:
            rel = d_iso(mm.group(1))
        prev = out.get(m.group(1), {})
        out[m.group(1)] = {**prev, "train": m.group(1), "label": m.group(1), "released": rel or prev.get("released", ""),
                           "eoas": "", "eoes": "", "eol": eol or prev.get("eol", ""), "latest": "", "latestDate": "",
                           "latestLink": it["url"], "lts": False, "type": "サポート終了" if eol and eol <= today().isoformat() else prev.get("type", ""),
                           "note": prev.get("note", ""), "maintained": None}
    if not out and not items:
        raise ValueError("RSS が空でした")
    return list(out.values())


FETCHERS = {"eol_date": fetch_eol_date, "juniper_eol": fetch_juniper, "arista_eos_rss": fetch_arista}


# ----------------------------------------------------------------------------
# 通知
# ----------------------------------------------------------------------------
def app_url() -> str:
    u = env("APP_URL")
    if not u and env("GITHUB_REPOSITORY"):
        owner, repo = env("GITHUB_REPOSITORY").split("/", 1)
        u = f"https://{owner}.github.io/{repo}/"
    return (u.rstrip("/") + "/fw/") if u else ""


def deep_link(pid: str, train: str = "") -> str:
    base = app_url()
    if not base:
        return "https://ntfy.sh"
    return base + (f"#/t/{urllib.parse.quote(pid, safe='')}/{urllib.parse.quote(train, safe='')}" if train else "")


FW_ICON = {"arrow_up": "⬆️", "new": "🆕", "hourglass": "⏳", "loudspeaker": "📢", "bell": "🔔"}
FW_COLOR = {"arrow_up": discord.COLOR["release"], "new": discord.COLOR["info"], "loudspeaker": discord.COLOR["MEDIUM"],
            "bell": discord.COLOR["info"]}


def push(title: str, message: str, click: str, prio: int = 3, tags: list | None = None) -> bool:
    tag = (tags or ["bell"])[0]
    if discord.enabled("fw"):
        color = (discord.COLOR["eol"] if prio >= 5 else discord.COLOR["eol_soon"]) if tag == "hourglass" else FW_COLOR.get(tag, discord.COLOR["info"])
        embed = {"title": discord.clip(title, 250), "description": discord.clip(message, 1500)
                 + (f"\n\n[アプリで開く]({click})" if click.startswith("http") and "ntfy.sh" not in click else ""),
                 "color": color, "footer": {"text": "FW・EOLウォッチ"}}
        if click.startswith("http") and "ntfy.sh" not in click:
            embed["url"] = click
        base = app_url()
        discord.send("fw", f"{FW_ICON.get(tag, '🔔')} {title}", embed, "FW・EOLウォッチ",
                     base + "icon-192.png" if base else "", urgent=prio >= 5, log=log)
    topic = env("NTFY_TOPIC")
    if not topic:
        if not discord.enabled("fw"):
            log(f"  [通知:未設定のため表示のみ] {title} / {message}")
        return True
    body = {"topic": topic, "title": title, "message": message, "priority": prio, "tags": tags or [], "click": click}
    base = app_url()
    if base:
        body["icon"] = base + "icon-192.png"
    hdr = {"Content-Type": "application/json", "User-Agent": lib.UA}
    if env("NTFY_TOKEN"):
        hdr["Authorization"] = f"Bearer {env('NTFY_TOKEN')}"
    req = urllib.request.Request(env("NTFY_SERVER", "https://ntfy.sh").rstrip("/") + "/",
                                 data=json.dumps(body).encode("utf-8"), headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        return True
    except Exception as e:  # noqa: BLE001
        log(f"  通知送信失敗: {e}")
        return False


# ----------------------------------------------------------------------------
def is_maintained(t: dict, d: dt.date) -> bool:
    if t.get("maintained") is not None:
        return bool(t["maintained"])
    return not t.get("eol") or t["eol"] >= d.isoformat()


def main() -> int:
    with open(CONFIG, encoding="utf-8") as f:
        cfg = json.load(f)
    if env("FW_CONFIG_OVERRIDE"):  # テスト用
        cfg.update(json.loads(env("FW_CONFIG_OVERRIDE")))
    first_run = not os.path.exists(STATE)
    st = {"trains": {}, "eol_notified": {}, "feed_seen": {}, "events": [], "products": {}}
    if not first_run:
        with open(STATE, encoding="utf-8") as f:
            st.update(json.load(f))
    d = today()
    mine = {x.strip() for x in env("MY_TRAINS").split(",") if ":" in x}
    mode_rel, mode_eol = env("NOTIFY_RELEASES", "mine"), env("NOTIFY_EOL", "mine")
    runs, products, new_events, pushes = [], [], [], []

    def add_event(ev: dict, notify: tuple | None = None):
        ev.setdefault("at", now_iso())
        ev["id"] = hashlib.sha1(json.dumps([ev["type"], ev.get("product"), ev.get("train"), ev.get("version"),
                                            ev.get("title")], ensure_ascii=False).encode()).hexdigest()[:12]
        if any(e["id"] == ev["id"] for e in st["events"] + new_events):
            return
        new_events.append(ev)
        if notify and not first_run:
            pushes.append(notify)

    # 1) 製品ごとのリリース系列
    for p in cfg["products"]:
        if not p.get("enabled", True):
            continue
        try:
            trains = FETCHERS[p["source"]](p)
            if p["source"] == "arista_eos_rss":  # RSS は最近の告知しか載らないので過去分と合わせる
                prev = {t["train"]: t for t in st["products"].get(p["id"], [])}
                prev.update({t["train"]: t for t in trains})
                trains = list(prev.values())
            st["products"][p["id"]] = trains
            runs.append({"source": p["name"], "vendor": p["vendor"], "ok": True, "count": len(trains), "error": "", "at": now_iso()})
            log(f"[{p['name']}] {len(trains)}系列")
        except Exception as e:  # noqa: BLE001  失敗したら前回のデータを使い続ける
            trains = st["products"].get(p["id"], [])
            runs.append({"source": p["name"], "vendor": p["vendor"], "ok": False, "count": len(trains), "error": str(e)[:200], "at": now_iso()})
            log(f"[{p['name']}] 取得失敗: {e}")
        trains.sort(key=lambda t: vkey(t["train"]), reverse=True)
        products.append({"id": p["id"], "vendor": p["vendor"], "name": p["name"], "source": p["source"],
                         "link": p.get("link", ""), "trains": trains})

    for pc in cfg["products"]:
        if not pc.get("matrix_image"):
            continue
        try:
            h = hashlib.sha1(lib.http_get(pc["matrix_image"], timeout=40)).hexdigest()
            key = f"matrix:{pc['id']}"
            if st.get(key) and st[key] != h:
                add_event({"type": "news", "vendor": pc["vendor"], "product": pc["id"],
                           "title": f"{pc['name']} のサポート表が更新されました（新しい系列の追加や日付の変更）",
                           "url": pc.get("link", ""), "date": d.isoformat()},
                          (f"{VENDOR_NAME.get(pc['vendor'], pc['vendor'])} · {pc['name']} サポート表の更新",
                           "公式のサポート表（画像）が更新されました。新しい系列や日付を確認して、collector_fw/config.json の baseline を更新してください。",
                           pc.get("link", "") or deep_link(pc["id"]), 4, ["loudspeaker"]))
            st[key] = h
        except Exception as e:  # noqa: BLE001
            log(f"[{pc['name']}] サポート表の確認に失敗: {e}")

    for p in products:
        for t in p["trains"]:
            known = st["trains"].get(f"{p['id']}:{t['train']}") or {}
            if known.get("latest") and vkey(known["latest"]) > vkey(t["latest"]):
                t.update(latest=known["latest"], latestDate=known.get("latestDate") or t["latestDate"],
                         latestLink=known.get("latestLink") or t["latestLink"])

    # 2) 公式RSS（Fortinet ファームウェア / Arista 告知）
    for fd in cfg.get("feeds", []):
        try:
            items = lib.parse_rss(lib.http_get(fd["url"], timeout=40), {"vendor": fd["vendor"]})
            runs.append({"source": fd["name"], "vendor": fd["vendor"], "ok": True, "count": len(items), "error": "", "at": now_iso()})
        except Exception as e:  # noqa: BLE001
            runs.append({"source": fd["name"], "vendor": fd["vendor"], "ok": False, "count": 0, "error": str(e)[:200], "at": now_iso()})
            log(f"[{fd['name']}] 取得失敗: {e}")
            continue
        rre = re.compile(fd["release_regex"]) if fd.get("release_regex") else None
        cutoff = (d - dt.timedelta(days=45)).isoformat()
        for it in items:
            key = it["url"] or it["adv_id"]
            if key in st["feed_seen"]:
                continue
            st["feed_seen"][key] = d.isoformat()
            date = (it["published"] or "")[:10]
            if date and date < cutoff:
                continue
            ev = {"type": "news", "vendor": fd["vendor"], "title": it["title"], "url": it["url"], "date": date or d.isoformat(),
                  "summary": (it["summary"] or "")[:300]}
            m = rre.search(it["title"]) if rre else None
            if m:
                pname, ver = m.group(1).strip(), m.group(2)
                ev.update(type="release", productName=pname, version=ver)
                # FortiOS なら endoflife.date より新しい場合に最新版を更新する
                for p in products:
                    if p["name"].lower() == pname.lower():
                        tr = ".".join(ver.split(".")[:2])
                        for t in p["trains"]:
                            if t["train"] == tr and vkey(ver) > vkey(t["latest"]):
                                t.update(latest=ver, latestDate=date or d.isoformat(), latestLink=it["url"])
                        ev.update(product=p["id"], train=tr)
                if not ev.get("product"):  # 追跡していない製品（FortiManager など）だけタイムラインに載せる
                    add_event(ev)
            else:
                hit = any(f"arista-eos:{t}" in mine for t in re.findall(r"\bEOS[\s-]+(4\.\d+)", it["title"]))
                add_event(ev, ("Arista · " + it["title"][:60], (it["summary"] or "")[:200], it["url"] or deep_link("arista-eos"),
                               4 if hit else 3, ["loudspeaker"]) if (mode_rel != "none" and (hit or not mine or mode_rel == "all")) else None)
        # 古い既読記録は捨てる
        old = (d - dt.timedelta(days=400)).isoformat()
        st["feed_seen"] = {k: v for k, v in st["feed_seen"].items() if v >= old}

    # 3) 新バージョン・新系列の検知
    def targeted(key: str, t: dict, mode: str) -> bool:
        if mode == "none":
            return False
        if mode == "all" or not mine:
            return is_maintained(t, d)
        return key in mine

    known_products = {k.split(":", 1)[0] for k in st["trains"]}  # 前回までに見たことのある製品
    for p in products:
        for t in p["trains"]:
            key = f"{p['id']}:{t['train']}"
            prev = st["trains"].get(key)
            label = f"{p['name']} {t['train']}"
            if prev is None:
                st["trains"][key] = {"latest": t["latest"], "latestDate": t["latestDate"], "latestLink": t["latestLink"]}
                # 既知の製品に新しい系列が増えたときだけ「新系列」として扱う（初めて取得できた製品は記録のみ）
                src = next((c.get("source") for c in cfg["products"] if c["id"] == p["id"]), "")
                if not first_run and p["id"] in known_products and is_maintained(t, d) and src != "arista_eos_rss":
                    if True:  # noqa: SIM108
                        add_event({"type": "train", "vendor": p["vendor"], "product": p["id"], "train": t["train"],
                                   "title": f"{label} が登場", "date": t["released"] or d.isoformat(), "version": t["latest"]},
                                  (f"{p['name']} · 新しいリリース系列", f"{label} が公開されました"
                                   + (f"（サポート終了 {t['eol']}）" if t["eol"] else ""), deep_link(p["id"], t["train"]), 4, ["new"])
                                  if mode_rel != "none" else None)
                elif first_run and t["latest"] and t["latestDate"] >= (d - dt.timedelta(days=30)).isoformat():
                    add_event({"type": "release", "vendor": p["vendor"], "product": p["id"], "train": t["train"],
                               "version": t["latest"], "title": f"{p['name']} {t['latest']}", "date": t["latestDate"],
                               "url": t["latestLink"]})
                continue
            if t["latest"] and t["latest"] != prev.get("latest") and vkey(t["latest"]) >= vkey(prev.get("latest", "")):
                prev.update(latest=t["latest"], latestDate=t["latestDate"], latestLink=t["latestLink"])
                add_event({"type": "release", "vendor": p["vendor"], "product": p["id"], "train": t["train"],
                           "version": t["latest"], "title": f"{p['name']} {t['latest']}", "date": t["latestDate"] or d.isoformat(),
                           "url": t["latestLink"]},
                          (f"{p['name']} · 新バージョン", f"{t['latest']} が公開されました（{label}系）"
                           + (f"\nサポート終了 {t['eol']}" if t["eol"] else ""), deep_link(p["id"], t["train"]),
                           4 if key in mine else 3, ["arrow_up"]) if targeted(key, t, mode_rel) else None)

    # 4) サポート終了の接近
    ths = sorted(int(x) for x in cfg["notify"]["eol_days"])
    for p in products:
        for t in p["trains"]:
            if not t["eol"]:
                continue
            key = f"{p['id']}:{t['train']}"
            days = (dt.date.fromisoformat(t["eol"]) - d).days
            done = set(st["eol_notified"].get(key, []))
            crossed = [th for th in ths if days <= th and th not in done]
            if not crossed:
                continue
            st["eol_notified"][key] = sorted(done | set(crossed))
            if days < -3 or not targeted(key, dict(t, maintained=None, eol=max(t["eol"], (d - dt.timedelta(days=3)).isoformat())), mode_eol):
                continue
            th = min(crossed)
            label = f"{p['name']} {t['train']}"
            msg = "本日サポート終了" if days <= 0 else f"サポート終了まであと{days}日"
            add_event({"type": "eol", "vendor": p["vendor"], "product": p["id"], "train": t["train"], "title": f"{label}：{msg}",
                       "date": d.isoformat(), "eolDate": t["eol"], "threshold": th},
                      (f"{label} · {msg}", f"サポート終了日 {t['eol']}" + (f"／最新 {t['latest']}" if t["latest"] else ""),
                       deep_link(p["id"], t["train"]), 5 if days <= 30 else 4, ["hourglass"]))

    # 5) 通知
    if first_run and not env("NOTIFY_INITIAL"):
        log(f"初回実行のため通知はスキップ（{len(new_events)}件の出来事を記録）")
    else:
        limit = int(cfg["notify"]["max_push_per_run"])
        for n in pushes[:limit]:
            push(*n)
        if len(pushes) > limit:
            push(f"ほか {len(pushes) - limit}件のお知らせ", "アプリで確認してください", app_url() or "https://ntfy.sh", 3, ["bell"])

    # 6) 書き出し（中身が変わったときだけ）
    st["events"] = (new_events + st["events"])[: int(cfg.get("keep_events", 300))]
    public = {"products": products, "events": st["events"], "runs": runs}
    digest = hashlib.sha1(json.dumps([products, st["events"], [(r["source"], r["ok"]) for r in runs]],
                                     ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    if digest != st.get("out_hash") or not os.path.exists(OUT):
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(dict(public, generated=now_iso(), today=d.isoformat()), f, ensure_ascii=False, separators=(",", ":"))
        st["out_hash"] = digest
        log("アプリ用データを更新")
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, separators=(",", ":"))
    log(f"完了: 新しい出来事 {len(new_events)}件 / 通知 {0 if first_run and not env('NOTIFY_INITIAL') else min(len(pushes), int(cfg['notify']['max_push_per_run']))}件")
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as f:
            f.write("### fwwatch\n| 取得元 | 結果 | 件数 |\n|---|---|---|\n")
            for r in runs:
                f.write(f"| {r['source']} | {'✅' if r['ok'] else '❌ ' + r['error'][:80]} | {r['count']} |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
