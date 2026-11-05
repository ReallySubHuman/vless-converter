import os
import re
import json
import base64
import binascii
import requests
from urllib.parse import urlencode, quote

SOURCE_URL = os.environ["SOURCE_URL"]
CUSTOM_UA = os.environ.get("USER_AGENT", "").strip()

OUTPUT_PLAIN = "vless.txt"
OUTPUT_B64 = "sub.txt"
MAX_DEPTH = 6

# Источник отдаёт HTML-заглушку браузерам и подписку только VPN-клиентам
CLIENT_USER_AGENTS = [
    "Happ/2.7.0",
    "v2rayNG/1.9.46",
    "Hiddify/2.0.5",
    "sing-box/1.10.0",
    "Streisand/1.6.0",
    "v2rayN/7.0.0",
]

B64_RE = re.compile(r"^[A-Za-z0-9+/_\-=\s]+$")
VLESS_RE = re.compile(r"vless://[^\s\"'<>\\]+")


# ---------------------------------------------------------------------------
# Сборка vless:// ссылки
# ---------------------------------------------------------------------------
def make_link(uuid, server, port, name, security="none", network="tcp",
              extra=None):
    if not uuid or not server or not port:
        return None

    params = {
        "encryption": "none",
        "security": security or "none",
        "type": network or "tcp",
    }

    for key, value in (extra or {}).items():
        if value not in (None, "", [], {}):
            if isinstance(value, list):
                value = ",".join(map(str, value))
            params[key] = value

    server = str(server)
    if ":" in server and not server.startswith("["):  # IPv6
        server = f"[{server}]"

    query = urlencode(params, quote_via=quote)
    return f"vless://{uuid}@{server}:{port}?{query}#{quote(str(name))}"


# ---------------------------------------------------------------------------
# Xray
# ---------------------------------------------------------------------------
def xray_extra(stream, user_flow=""):
    security = stream.get("security", "none")
    network = stream.get("network", "tcp")

    tls = stream.get("tlsSettings", {}) or {}
    reality = stream.get("realitySettings", {}) or {}
    sec = reality if security == "reality" else tls

    ws = stream.get("wsSettings", {}) or {}
    grpc = stream.get("grpcSettings", {}) or {}
    xhttp = stream.get("xhttpSettings", {}) or stream.get("splithttpSettings", {}) or {}
    hu = stream.get("httpupgradeSettings", {}) or {}

    path = host = service_name = mode = ""

    if network == "ws":
        path = ws.get("path", "")
        host = ws.get("host") or (ws.get("headers", {}) or {}).get("Host", "")
    elif network == "grpc":
        service_name = grpc.get("serviceName", "")
        mode = "multi" if grpc.get("multiMode") else ""
    elif network in ("xhttp", "splithttp"):
        path = xhttp.get("path", "")
        host = xhttp.get("host", "")
        mode = xhttp.get("mode", "")
    elif network == "httpupgrade":
        path = hu.get("path", "")
        host = hu.get("host", "")

    return {
        "sni": sec.get("serverName", ""),
        "fp": sec.get("fingerprint", ""),
        "pbk": sec.get("publicKey", ""),
        "sid": sec.get("shortId", ""),
        "spx": sec.get("spiderX", ""),
        "alpn": sec.get("alpn", ""),
        "allowInsecure": "1" if sec.get("allowInsecure") else "",
        "flow": user_flow,
        "path": path,
        "host": host,
        "serviceName": service_name,
        "mode": mode,
    }


def convert_xray(obj):
    result = []

    if obj.get("protocol") != "vless":
        return result

    settings = obj.get("settings", {}) or {}
    stream = obj.get("streamSettings", {}) or {}
    security = stream.get("security", "none")
    network = stream.get("network", "tcp")
    tag = obj.get("tag", "VLESS")

    # Классический формат: settings.vnext[].users[]
    for server in settings.get("vnext", []) or []:
        for user in server.get("users", []) or []:
            link = make_link(
                uuid=user.get("id"),
                server=server.get("address"),
                port=server.get("port"),
                name=user.get("email") or tag,
                security=security,
                network=network,
                extra=xray_extra(stream, user.get("flow", "")),
            )
            if link:
                result.append(link)

    # Новый плоский формат: settings.address/port/id
    if settings.get("address") and settings.get("id"):
        link = make_link(
            uuid=settings.get("id"),
            server=settings.get("address"),
            port=settings.get("port"),
            name=tag,
            security=security,
            network=network,
            extra=xray_extra(stream, settings.get("flow", "")),
        )
        if link:
            result.append(link)

    return result


# ---------------------------------------------------------------------------
# sing-box
# ---------------------------------------------------------------------------
def convert_singbox(obj):
    if obj.get("type") != "vless":
        return []

    tls = obj.get("tls", {}) or {}
    transport = obj.get("transport", {}) or {}
    reality = tls.get("reality", {}) or {}
    utls = tls.get("utls", {}) or {}

    security = (
        "reality" if reality.get("enabled")
        else "tls" if tls.get("enabled")
        else "none"
    )

    network = transport.get("type", "tcp")
    headers = transport.get("headers", {}) or {}

    host = transport.get("host", "") or headers.get("Host", "")
    if isinstance(host, list):
        host = ",".join(host)

    extra = {
        "sni": tls.get("server_name", ""),
        "fp": utls.get("fingerprint", ""),
        "pbk": reality.get("public_key", ""),
        "sid": reality.get("short_id", ""),
        "alpn": tls.get("alpn", ""),
        "allowInsecure": "1" if tls.get("insecure") else "",
        "flow": obj.get("flow", ""),
        "path": transport.get("path", ""),
        "host": host,
        "serviceName": transport.get("service_name", ""),
    }

    link = make_link(
        uuid=obj.get("uuid"),
        server=obj.get("server"),
        port=obj.get("server_port"),
        name=obj.get("tag", "VLESS"),
        security=security,
        network=network,
        extra=extra,
    )
    return [link] if link else []


# ---------------------------------------------------------------------------
# Распаковка: base64 / JSON / текст
# ---------------------------------------------------------------------------
def try_b64(text):
    """Пробует декодировать base64. Возвращает строку или None."""
    compact = "".join(text.split())
    if len(compact) < 16 or not B64_RE.match(compact):
        return None

    compact += "=" * (-len(compact) % 4)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(compact).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        stripped = decoded.lstrip()
        if "://" in decoded or stripped.startswith(("{", "[")):
            return decoded

    return None


def parse_content(text, depth=0):
    """Универсальный разбор: JSON, base64, список строк."""
    if depth > MAX_DEPTH or not isinstance(text, str):
        return []

    text = text.strip()
    if not text:
        return []

    links = []

    # 1) Целиком JSON
    if text[0] in "{[":
        try:
            return scan(json.loads(text), depth + 1)
        except ValueError:
            pass

    # 2) Целиком base64
    decoded = try_b64(text)
    if decoded:
        return parse_content(decoded, depth + 1)

    # 3) Построчно
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("vless://"):
            links.append(line)
        elif line[0] in "{[":
            try:
                links.extend(scan(json.loads(line), depth + 1))
            except ValueError:
                pass
        else:
            decoded = try_b64(line)
            if decoded:
                links.extend(parse_content(decoded, depth + 1))

    return links


def scan(obj, depth=0):
    links = []

    if depth > MAX_DEPTH:
        return links

    if isinstance(obj, dict):
        links.extend(convert_xray(obj))
        links.extend(convert_singbox(obj))
        for value in obj.values():
            links.extend(scan(value, depth + 1))

    elif isinstance(obj, list):
        for item in obj:
            links.extend(scan(item, depth + 1))

    elif isinstance(obj, str):
        if "vless://" in obj or obj.lstrip().startswith(("{", "[")) or len(obj) > 40:
            links.extend(parse_content(obj, depth + 1))

    return links


# ---------------------------------------------------------------------------
# Загрузка
# ---------------------------------------------------------------------------
def download(url, user_agent):
    response = requests.get(
        url,
        timeout=60,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
    )
    response.raise_for_status()
    return response.text, response.headers.get("Content-Type", "")


def looks_like_html(text):
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def extract(text):
    """Основной разбор + запасной поиск vless:// регуляркой."""
    if looks_like_html(text):
        return []

    found = parse_content(text)
    if not found:
        found = VLESS_RE.findall(text)
    return found


def fetch_links(url):
    agents = [CUSTOM_UA] if CUSTOM_UA else CLIENT_USER_AGENTS

    for ua in agents:
        try:
            text, ctype = download(url, ua)
        except requests.RequestException as e:
            print(f"  [{ua}] download error: {e}")
            continue

        found = extract(text)
        print(f"  [{ua}] content-type={ctype!r}, {len(text)} bytes, "
              f"found {len(found)} configs")

        if found:
            return found

        preview = text.strip()[:200].replace("\n", " ")
        print(f"  [{ua}] preview: {preview}")

    return []


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    urls = [u for u in re.split(r"[\s,]+", SOURCE_URL.strip()) if u]
    all_links = []

    for url in urls:
        print("Downloading subscription...")
        all_links.extend(fetch_links(url))

    links = list(dict.fromkeys(all_links))

    if not links:
        raise Exception("No VLESS configs found!")

    plain = "\n".join(links) + "\n"

    with open(OUTPUT_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain)

    with open(OUTPUT_B64, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain.encode("utf-8")).decode("ascii"))

    print(f"Successfully converted {len(links)} configs!")


if __name__ == "__main__":
    main()
