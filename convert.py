import os
import json
import requests
from urllib.parse import urlencode, quote

SOURCE_URL = os.environ["SOURCE_URL"]
OUTPUT = "vless.txt"


def make_link(uuid, server, port, name, security="none",
              network="tcp", sni="", fp="", pbk="", sid="",
              flow="", path="", host="", service_name=""):

    if not uuid or not server or not port:
        return None

    params = {
        "encryption": "none",
        "security": security,
        "type": network
    }

    optional = {
        "sni": sni,
        "fp": fp,
        "pbk": pbk,
        "sid": sid,
        "flow": flow,
        "path": path,
        "host": host,
        "serviceName": service_name
    }

    for key, value in optional.items():
        if value:
            params[key] = value

    query = urlencode(params, quote_via=quote)

    return (
        f"vless://{uuid}@{server}:{port}"
        f"?{query}#{quote(str(name))}"
    )


def convert_xray(obj):
    result = []

    if obj.get("protocol") != "vless":
        return result

    settings = obj.get("settings", {})
    stream = obj.get("streamSettings", {})

    security = stream.get("security", "none")
    network = stream.get("network", "tcp")

    tls = stream.get("tlsSettings", {})
    reality = stream.get("realitySettings", {})

    sec = reality if security == "reality" else tls

    transport = stream.get("wsSettings", {})
    grpc = stream.get("grpcSettings", {})

    path = transport.get("path", "")
    headers = transport.get("headers", {})
    host = headers.get("Host", "")

    for server in settings.get("vnext", []):
        for user in server.get("users", []):

            link = make_link(
                uuid=user.get("id"),
                server=server.get("address"),
                port=server.get("port"),
                name=user.get("email", obj.get("tag", "VLESS")),
                security=security,
                network=network,
                sni=sec.get("serverName", ""),
                fp=sec.get("fingerprint", ""),
                pbk=sec.get("publicKey", ""),
                sid=sec.get("shortId", ""),
                flow=user.get("flow", ""),
                path=path,
                host=host,
                service_name=grpc.get("serviceName", "")
            )

            if link:
                result.append(link)

    return result


def convert_singbox(obj):
    if obj.get("type") != "vless":
        return []

    tls = obj.get("tls", {})
    transport = obj.get("transport", {})

    reality = tls.get("reality", {})
    utls = tls.get("utls", {})

    security = (
        "reality" if reality.get("enabled")
        else "tls" if tls.get("enabled")
        else "none"
    )

    headers = transport.get("headers", {})

    link = make_link(
        uuid=obj.get("uuid"),
        server=obj.get("server"),
        port=obj.get("server_port"),
        name=obj.get("tag", "VLESS"),
        security=security,
        network=transport.get("type", "tcp"),
        sni=tls.get("server_name", ""),
        fp=utls.get("fingerprint", ""),
        pbk=reality.get("public_key", ""),
        sid=reality.get("short_id", ""),
        flow=obj.get("flow", ""),
        path=transport.get("path", ""),
        host=headers.get("Host", ""),
        service_name=transport.get("service_name", "")
    )

    return [link] if link else []


def scan(obj):
    links = []

    if isinstance(obj, dict):
        links.extend(convert_xray(obj))
        links.extend(convert_singbox(obj))

        for value in obj.values():
            links.extend(scan(value))

    elif isinstance(obj, list):
        for item in obj:
            links.extend(scan(item))

    elif isinstance(obj, str):
        for line in obj.splitlines():
            if line.strip().startswith("vless://"):
                links.append(line.strip())

    return links


def main():
    print("Downloading subscription...")

    response = requests.get(
        SOURCE_URL,
        timeout=60,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    response.raise_for_status()

    data = response.json()

    links = list(dict.fromkeys(scan(data)))

    if not links:
        raise Exception("No VLESS configs found!")

    with open(OUTPUT, "w", encoding="utf-8") as file:
        file.write("\n".join(links) + "\n")

    print(f"Successfully converted {len(links)} configs!")


if __name__ == "__main__":
    main()
