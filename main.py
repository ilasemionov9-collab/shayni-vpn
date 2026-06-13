#!/usr/bin/env python3
"""
Парсер подписок из Telegram-канала @hiddifycode.
Находит топ-3 самых быстрых сервера (реальная задержка через туннель + скорость)
и записывает их в vpn.yml в формате Clash/Mihomo (понимают Happ, Hiddify, v2rayTun и др.).
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import requests
import yaml

# ---------- Настройки ----------
TG_CHANNEL = "https://t.me/s/hiddifycode"            # публичная веб-версия канала
DELAY_TEST_URL = "http://www.gstatic.com/generate_204"
DELAY_TIMEOUT = 5000              # мс на одну проверку задержки
TOP_N_FOR_SPEEDTEST = 8          # сколько лучших по задержке гнать на тест скорости
FINAL_TOP = 3                    # сколько серверов записать в файл
SPEEDTEST_BYTES = 10 * 1024 * 1024                  # 10 МБ тестовая загрузка
SPEEDTEST_URL = f"https://speed.cloudflare.com/__down?bytes={SPEEDTEST_BYTES}"

CONTROLLER = "127.0.0.1:9090"
MIXED_PORT = 7890
WORKDIR = Path("./.mihomo")
OUTPUT_FILE = Path("vpn.yml")
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "./mihomo")
SUB_OVERRIDE = os.environ.get("SUBSCRIPTION_URL", "").strip()
API = f"http://{CONTROLLER}"
LOCAL_PROXY = {"http": f"http://127.0.0.1:{MIXED_PORT}",
               "https": f"http://127.0.0.1:{MIXED_PORT}"}


# ---------- Утилиты ----------
def try_b64(s):
    """Пытается декодировать base64 (обычный и url-safe)."""
    s = s.strip().replace("\n", "").replace("\r", "")
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            pad = "=" * (-len(s) % 4)
            return decoder(s + pad).decode("utf-8", "ignore")
        except Exception:
            continue
    return None


# ---------- 1. Telegram ----------
def fetch_channel_html():
    r = requests.get(TG_CHANNEL, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
    r.raise_for_status()
    return r.text


def extract_candidate_urls(html):
    """Достаёт все внешние ссылки из канала, новые — в конце."""
    urls = re.findall(r'https?://[^\s"<>]+', html)
    bad = ("t.me", "telegram.org", "cdn-telegram", "telesco.pe",
           "google", "gstatic", "fonts", ".png", ".jpg", ".css", ".js")
    seen, out = set(), []
    for u in urls:
        u = u.rstrip('".,)\'')
        if any(b in u for b in bad) or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def try_subscription(url):
    """Проверяет, является ли ссылка рабочей подпиской. Возвращает сырые байты."""
    try:
        r = requests.get(url, headers={"User-Agent": "clash.meta"}, timeout=30)
        if r.status_code != 200 or not r.content:
            return None
    except Exception:
        return None
    text = r.text.strip()
    if "proxies:" in text:                       # уже Clash YAML
        return r.content
    dec = try_b64(text)
    if dec and re.search(r"(vless|vmess|trojan|ss|hysteria2?|tuic)://", dec):
        return r.content                          # base64-список ссылок
    if re.search(r"(vless|vmess|trojan|ss)://", text):
        return r.content                          # plain-список ссылок
    return None


def get_subscription():
    if SUB_OVERRIDE:
        print(f"→ Использую SUBSCRIPTION_URL из секрета")
        data = try_subscription(SUB_OVERRIDE)
        if data:
            return data
        print("✗ Заданный SUBSCRIPTION_URL не похож на подписку")
        sys.exit(1)

    print("→ Читаю Telegram-канал @hiddifycode...")
    html = fetch_channel_html()
    candidates = list(reversed(extract_candidate_urls(html)))  # новые первыми
    print(f"  ссылок-кандидатов: {len(candidates)}")
    for url in candidates:
        data = try_subscription(url)
        if data:
            print(f"  ✓ рабочая подписка: {url}")
            return data
    print("✗ Не нашёл рабочую подписку в канале")
    sys.exit(1)


# ---------- 2. Парсинг ссылок в Clash-формат ----------
def _qs(uri):
    parsed = urllib.parse.urlparse(uri)
    q = dict(urllib.parse.parse_qsl(parsed.query))
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else parsed.hostname
    return parsed, q, name


def parse_vmess(uri):
    js = try_b64(uri[len("vmess://"):])
    if not js:
        return None
    v = json.loads(js)
    net = v.get("net", "tcp")
    p = {"name": v.get("ps") or v.get("add"), "type": "vmess",
         "server": v.get("add"), "port": int(v.get("port", 443)),
         "uuid": v.get("id"), "alterId": int(v.get("aid", 0) or 0),
         "cipher": v.get("scy") or "auto", "udp": True, "network": net}
    if str(v.get("tls", "")).lower() in ("tls", "reality"):
        p["tls"] = True
        if v.get("sni") or v.get("host"):
            p["servername"] = v.get("sni") or v.get("host")
    host, path = v.get("host", ""), v.get("path", "")
    if net == "ws":
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": path or ""}
    return p


def parse_vless(uri):
    parsed, q, name = _qs(uri)
    p = {"name": name, "type": "vless", "server": parsed.hostname,
         "port": int(parsed.port or 443), "uuid": parsed.username,
         "udp": True, "network": q.get("type", "tcp")}
    sec = q.get("security", "")
    if q.get("flow"):
        p["flow"] = q["flow"]
    if q.get("fp"):
        p["client-fingerprint"] = q["fp"]
    if sec in ("tls", "reality"):
        p["tls"] = True
        if q.get("sni"):
            p["servername"] = q["sni"]
        if q.get("alpn"):
            p["alpn"] = q["alpn"].split(",")
    if sec == "reality":
        ro = {}
        if q.get("pbk"):
            ro["public-key"] = q["pbk"]
        if q.get("sid"):
            ro["short-id"] = q["sid"]
        p["reality-opts"] = ro
    net, host = p["network"], q.get("host", "")
    if net == "ws":
        opts = {"path": q.get("path", "/")}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return p


def parse_trojan(uri):
    parsed, q, name = _qs(uri)
    p = {"name": name, "type": "trojan", "server": parsed.hostname,
         "port": int(parsed.port or 443),
         "password": urllib.parse.unquote(parsed.username or ""), "udp": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("alpn"):
        p["alpn"] = q["alpn"].split(",")
    net = q.get("type", "tcp")
    if net == "ws":
        opts = {"path": q.get("path", "/")}
        if q.get("host"):
            opts["headers"] = {"Host": q["host"]}
        p["network"], p["ws-opts"] = "ws", opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return p


def parse_ss(uri):
    body = uri[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urllib.parse.unquote(frag)
    if "@" in body:
        creds, server_part = body.rsplit("@", 1)
        dec = try_b64(creds)
        if dec and ":" in dec:
            method, password = dec.split(":", 1)
        else:
            method, password = urllib.parse.unquote(creds).split(":", 1)
    else:
        dec = try_b64(body)
        creds, server_part = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
    server_part = server_part.split("?", 1)[0].split("/", 1)[0]
    host, port = server_part.rsplit(":", 1)
    return {"name": name or host, "type": "ss", "server": host,
            "port": int(port), "cipher": method, "password": password, "udp": True}


def parse_uri(uri):
    try:
        if uri.startswith("vmess://"):
            return parse_vmess(uri)
        if uri.startswith("vless://"):
            return parse_vless(uri)
        if uri.startswith("trojan://"):
            return parse_trojan(uri)
        if uri.startswith("ss://"):
            return parse_ss(uri)
    except Exception as e:
        print(f"   ! не разобрал ноду: {e}")
    return None   # hysteria2 / tuic и пр. пропускаем


def parse_subscription(raw):
    text = raw.decode("utf-8", "ignore").strip()
    if "proxies:" in text:                       # Clash YAML
        data = yaml.safe_load(text) or {}
        return data.get("proxies", []) or []
    dec = try_b64(text)                           # blob base64?
    if dec and "://" in dec:
        text = dec
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            p = parse_uri(line)
            if p:
                proxies.append(p)
    return proxies


def dedupe(proxies):
    seen, out = {}, []
    for p in proxies:
        if not p or not p.get("server") or not p.get("name"):
            continue
        base = str(p["name"]).strip() or p["server"]
        name, i = base, 1
        while name in seen:
            i += 1
            name = f"{base} #{i}"
        seen[name] = True
        p["name"] = name
        out.append(p)
    return out


# ---------- 3. Ядро mihomo ----------
def write_mihomo_config(proxies):
    WORKDIR.mkdir(parents=True, exist_ok=True)
    cfg = {"mixed-port": MIXED_PORT, "mode": "global", "log-level": "silent",
           "unified-delay": True, "tcp-concurrent": True,
           "external-controller": CONTROLLER, "proxies": proxies}
    (WORKDIR / "config.yaml").write_text(
        yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")


def start_mihomo():
    proc = subprocess.Popen([MIHOMO_BIN, "-d", str(WORKDIR)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            requests.get(f"{API}/version", timeout=2)
            return proc
        except Exception:
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("mihomo не запустился")


def test_delay(name):
    try:
        r = requests.get(f"{API}/proxies/{urllib.parse.quote(name)}/delay",
                         params={"url": DELAY_TEST_URL, "timeout": DELAY_TIMEOUT},
                         timeout=DELAY_TIMEOUT / 1000 + 5)
        if r.status_code == 200:
            return r.json().get("delay")
    except Exception:
        return None
    return None


def select_global(name):
    try:
        requests.put(f"{API}/proxies/GLOBAL",
                     json={"name": name}, timeout=10)
    except Exception:
        pass


def test_speed(name):
    select_global(name)
    time.sleep(0.4)
    start, downloaded = time.time(), 0
    try:
        with requests.get(SPEEDTEST_URL, proxies=LOCAL_PROXY,
                          stream=True, timeout=30) as r:
            for chunk in r.iter_content(65536):
                downloaded += len(chunk)
                if time.time() - start > 15:
                    break
        elapsed = time.time() - start
        if elapsed > 0 and downloaded > 0:
            return downloaded / elapsed / 1024 / 1024     # МБ/с
    except Exception:
        return 0.0
    return 0.0


# ---------- 4. Запись результата ----------
def write_output(winner_dicts):
    names = [p["name"] for p in winner_dicts]
    out = {"proxies": winner_dicts,
           "proxy-groups": [
               {"name": "🚀 Авто", "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300, "tolerance": 50, "proxies": names},
               {"name": "🔰 Выбор", "type": "select",
                "proxies": ["🚀 Авто"] + names}],
           "rules": ["MATCH,🔰 Выбор"]}
    header = ("# Автообновление каждые 3 часа — топ-3 сервера по скорости\n"
              f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n")
    OUTPUT_FILE.write_text(
        header + yaml.safe_dump(out, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    print(f"✓ Записано в {OUTPUT_FILE}")


# ---------- main ----------
def main():
    raw = get_subscription()
    proxies = dedupe(parse_subscription(raw))
    print(f"  серверов в подписке: {len(proxies)}")
    if not proxies:
        print("✗ Подписка пустая или формат не поддержан")
        sys.exit(1)

    by_name = {p["name"]: p for p in proxies}
    write_mihomo_config(proxies)
    print("→ Запускаю ядро mihomo...")
    proc = start_mihomo()
    try:
        time.sleep(2)
        print("→ Замеряю реальную задержку через туннель (unified-delay)...")
        delays = []
        for p in proxies:
            d = test_delay(p["name"])
            if d:
                delays.append((p["name"], d))
        delays.sort(key=lambda x: x[1])
        if not delays:
            print("✗ Ни один сервер не ответил")
            sys.exit(1)
        print(f"  живых серверов: {len(delays)}")

        print("→ Тест скорости лучших по задержке...")
        scored = []
        for name, delay in delays[:TOP_N_FOR_SPEEDTEST]:
            spd = test_speed(name)
            scored.append((name, delay, spd))
            print(f"   {spd:6.2f} МБ/с | {delay:>4} мс | {name}")

        scored.sort(key=lambda x: (-x[2], x[1]))   # сначала скорость, потом пинг
        winners = scored[:FINAL_TOP]
        print("→ ТОП-3:")
        for name, d, s in winners:
            print(f"   ★ {name} | {d} мс | {s:.2f} МБ/с")

        write_output([by_name[name] for name, _, _ in winners])
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
