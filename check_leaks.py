#!/usr/bin/env python3
"""check_leaks.py

Скрипт извлекает хосты с портом из целевой подписки, берет все хосты
из локального `list.txt` (или извлекает их из URL-ов, если строки в
`list.txt` являются ссылками), и ищет совпадения (утечки).

Результат:
- leak_report.json
- leak_report.md

Опции:
  --target-url    URL подписки для проверки (по умолчанию тот же)
  --list-file     Путь к файлу со списком общедоступных подписок (default: list.txt)
  --user-agent    User-Agent для запросов (default: Happ/1.5.2/Windows)
  --create-issue  Создавать issue в GitHub (требуется GITHUB_TOKEN и GITHUB_REPOSITORY)

Возвращает ненулевой код только на неожиданных ошибках.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple

import requests

HOST_PORT_RE = re.compile(
    r"@(?P<h>(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9\-\.]+):\d{1,5})"
)
SIMPLE_HOST_PORT_RE = re.compile(
    r"(?P<h>(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9\-\.]+):\d{1,5})"
)
BASE64_CLEAN_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def is_base64_like(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    # Allow newlines/spaces in base64
    s2 = s.replace("\n", "").replace("\r", "").replace(" ", "")
    if not BASE64_CLEAN_RE.match(s2):
        return False
    # Heuristic length multiple of 4
    return len(s2) % 4 == 0


def try_base64_decode(s: str) -> Optional[str]:
    try:
        b = base64.b64decode(s, validate=True)
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return None
    except Exception:
        return None


def fetch_url(url: str, user_agent: str) -> Optional[str]:
    headers = {"User-Agent": user_agent}
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        text = r.text
        # If looks like base64, decode it
        if is_base64_like(text):
            dec = try_base64_decode(text)
            if dec is not None and dec.strip():
                return dec
        return text
    except Exception as e:
        print(f"Warning: failed to fetch {url}: {e}", file=sys.stderr)
        return None


def extract_hosts_from_text(text: str) -> Set[str]:
    hosts = set()
    for m in HOST_PORT_RE.finditer(text):
        hosts.add(m.group("h"))
    # If nothing found by @-anchor, fall back to any host:port matches
    if not hosts:
        for m in SIMPLE_HOST_PORT_RE.finditer(text):
            hosts.add(m.group("h"))
    return hosts


def parse_list_file(list_path: str, user_agent: str) -> Dict[str, Set[str]]:
    """Возвращает словарь: источник -> набор host:port"""
    sources: Dict[str, Set[str]] = {}
    if not os.path.exists(list_path):
        print(f"List file not found: {list_path}", file=sys.stderr)
        return sources

    with open(list_path, "r", encoding="utf-8", errors="ignore") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]

    for i, ln in enumerate(lines, start=1):
        key = f"{list_path}#L{i}"
        # Если выглядят как URL - попробуем получить и декодировать
        if ln.lower().startswith("http://") or ln.lower().startswith("https://"):
            content = fetch_url(ln, user_agent)
            if content:
                hosts = extract_hosts_from_text(content)
                sources[key] = hosts
            else:
                sources[key] = set()
        else:
            # Линия уже содержит готовый список хостов или одиночный host:port
            hosts = set()
            # Если линия содержит несколько элементов (через пробел или запятую)
            for part in re.split(r"[\s,;]+", ln):
                if SIMPLE_HOST_PORT_RE.fullmatch(part):
                    hosts.add(part)
                else:
                    # Попробуем извлечь элементы после @ если есть
                    for m in HOST_PORT_RE.finditer(part):
                        hosts.add(m.group("h"))
            if hosts:
                sources[key] = hosts
            else:
                # Попытка извлечь из самой строки
                hosts2 = extract_hosts_from_text(ln)
                sources[key] = hosts2

    return sources


def make_reports(
    target_url: str, target_hosts: Set[str], sources: Dict[str, Set[str]]
) -> Tuple[str, str, dict]:
    matches = []
    for host in sorted(target_hosts):
        for src, hosts in sources.items():
            if host in hosts:
                matches.append({"host": host, "source": src})

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "target_hosts": sorted(list(target_hosts)),
        "sources_count": len(sources),
        "matches": matches,
    }

    json_path = "leak_report.json"
    md_path = "leak_report.md"

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    # Simple markdown summary
    lines = []
    lines.append("# Leak report")
    lines.append(f"- Generated: {report['timestamp']}")
    lines.append(f"- Target: {target_url}")
    lines.append(f"- Found hosts in target: {len(target_hosts)}")
    lines.append(f"- Sources scanned: {len(sources)}")
    lines.append(f"- Matches: {len(matches)}")
    lines.append("")

    if matches:
        lines.append("## Matches")
        for m in matches:
            lines.append(f"- **{m['host']}** found in `{m['source']}`")
    else:
        lines.append("No leaks found.")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return json_path, md_path, report


def create_github_issue(report: dict, token: str, repository: str) -> Optional[str]:
    # repository format: owner/repo
    url = f"https://api.github.com/repos/{repository}/issues"
    title = f"Host leak report: {len(report.get('matches', []))} matches ({report.get('timestamp')})"
    body_lines = [
        f"**Target**: {report.get('target_url')}",
        f"**Found hosts**: {len(report.get('target_hosts', []))}",
        f"**Matches**: {len(report.get('matches', []))}",
        "",
        "Matches details:",
    ]
    for m in report.get("matches", []):
        body_lines.append(f"- {m['host']} — found in {m['source']}")
    body = "\n".join(body_lines)

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "host-leak-checker",
    }
    try:
        r = requests.post(
            url, json={"title": title, "body": body}, headers=headers, timeout=15
        )
        r.raise_for_status()
        data = r.json()
        issue_url = data.get("html_url")
        print(f"Created GitHub issue: {issue_url}")
        return issue_url
    except Exception as e:
        print(f"Error creating GitHub issue: {e}", file=sys.stderr)
        return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Check subscription for host leaks. Usage: check_leaks.py <target_url> <list_file> [--user-agent ...] [--create-issue]"
    )
    p.add_argument(
        "target_url", help="URL подписки для проверки (первый позиционный аргумент)"
    )
    p.add_argument(
        "list_file",
        help="Путь к файлу со списком общедоступных подписок (второй позиционный аргумент)",
    )
    p.add_argument("--user-agent", default="Happ/1.5.2/Windows")
    p.add_argument("--create-issue", action="store_true")
    args = p.parse_args(argv)

    try:
        target_content = fetch_url(args.target_url, args.user_agent)
        if not target_content:
            print("Failed to fetch or decode target subscription.", file=sys.stderr)
            return 2

        target_hosts = extract_hosts_from_text(target_content)
        print(f"Found {len(target_hosts)} hosts in target subscription")

        sources = parse_list_file(args.list_file, args.user_agent)
        total_hosts_in_sources = sum(len(s) for s in sources.values())
        print(
            f"Loaded {len(sources)} sources with {total_hosts_in_sources} hosts total"
        )

        json_path, md_path, report = make_reports(
            args.target_url, target_hosts, sources
        )
        print(f"Reports written: {json_path}, {md_path}")

        create_issue_flag = (
            args.create_issue or os.getenv("CREATE_ISSUE", "").lower() == "true"
        )
        if create_issue_flag:
            token = os.getenv("GITHUB_TOKEN")
            repository = os.getenv("GITHUB_REPOSITORY")
            if token and repository:
                create_github_issue(report, token, repository)
            else:
                print(
                    "CREATE_ISSUE requested but GITHUB_TOKEN or GITHUB_REPOSITORY not set",
                    file=sys.stderr,
                )

        # Success exit (leaks may or may not be present)
        return 0

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
