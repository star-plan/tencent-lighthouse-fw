"""Public IPv4 discovery helpers."""

from __future__ import annotations

import ipaddress
import re

import requests


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _find_ipv4(text: str) -> str | None:
    match = IPV4_RE.search(text)
    return match.group(0) if match else None


def get_public_ipv4(ip_sources: tuple[str, ...], timeout_seconds: float) -> str:
    """Try each configured endpoint until a valid public IPv4 is found."""

    last_error: str | None = None
    headers = {"User-Agent": "lighthouse-fw/0.1.0"}
    for url in ip_sources:
        try:
            response = requests.get(url, timeout=timeout_seconds, headers=headers)
            response.raise_for_status()
            ip = _find_ipv4(response.text)
            if ip:
                ipaddress.IPv4Address(ip)
                return ip
            last_error = f"{url}: 没有提取到 IPv4"
        except Exception as exc:  # pragma: no cover - depends on user network
            last_error = f"{url}: {exc}"
    raise RuntimeError(f"无法从所有 IP 查询源获取公网 IPv4。最后一次错误：{last_error}")

