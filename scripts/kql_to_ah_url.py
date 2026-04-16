#!/usr/bin/env python3
"""Generate a Defender XDR Advanced Hunting deep link URL from a KQL query.

Encoding: UTF-16LE → GZip → Base64url (RFC 4648 §5)

The Defender portal decodes the query parameter as:
  Base64url decode → GZip decompress → UTF-16LE decode

Usage:
    # From a string (auto-reads tenant_id from config.json)
    python scripts/kql_to_ah_url.py "DeviceInfo | where Timestamp > ago(1d) | take 10"

    # Markdown link output (ready to paste into reports)
    python scripts/kql_to_ah_url.py --md "DeviceInfo | where Timestamp > ago(1d) | take 10"

    # From a .kql file
    python scripts/kql_to_ah_url.py --file temp/query.kql

    # From stdin (pipe)
    echo "DeviceInfo | take 10" | python scripts/kql_to_ah_url.py

    # Explicit tenant ID
    python scripts/kql_to_ah_url.py --tid "56a548c7-..." "DeviceInfo | take 10"

    # Suppress tenant ID even if config.json has one
    python scripts/kql_to_ah_url.py --no-tid "DeviceInfo | take 10"

Tenant ID resolution (in order):
    1. --no-tid flag → omit tid parameter
    2. --tid <GUID> → use explicit value
    3. config.json tenant_id field → auto-read from workspace root
    4. None of the above → omit tid parameter

Output:
    URL only (default), or markdown link (--md flag).

Rendering in reports:
    Place the link immediately after the KQL code block in every Take Action section:

        ```kql
        EmailEvents
        | where Timestamp > ago(7d)
        | where NetworkMessageId in ("<id1>", "<id2>")
        ```
        [Run in Advanced Hunting](<url>)
"""

import base64
import gzip
import io
import json
import sys
import argparse
from pathlib import Path


def _load_tenant_id() -> str | None:
    """Try to load tenant_id from config.json in the workspace root.

    Returns the tenant GUID if found and not a placeholder, else None.
    """
    # Walk up from this script's location to find config.json
    script_dir = Path(__file__).resolve().parent
    for candidate in [script_dir.parent, Path.cwd()]:
        config_path = candidate / "config.json"
        if config_path.is_file():
            try:
                with open(config_path, encoding="utf-8") as f:
                    config = json.load(f)
                tid = config.get("tenant_id", "")
                if tid and "YOUR_" not in tid and tid != "":
                    return tid
            except (json.JSONDecodeError, OSError):
                pass
    return None


def kql_to_ah_url(kql: str, tenant_id: str | None = None) -> str:
    """Encode a KQL query into a Defender XDR Advanced Hunting deep link.

    The portal expects: UTF-16LE bytes → GZip compressed → Base64url encoded.
    If tenant_id is provided, appends &tid=<tenant_id> for cross-tenant linking.
    """
    # Normalize line endings to CRLF (what the portal Monaco editor expects)
    kql = kql.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    # UTF-16LE encode
    kql_bytes = kql.encode("utf-16-le")

    # GZip compress
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(kql_bytes)
    compressed = buf.getvalue()

    # Base64url encode (RFC 4648 §5: +→-, /→_, no padding)
    b64 = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")

    url = f"https://security.microsoft.com/v2/advanced-hunting?query={b64}"
    if tenant_id:
        url += f"&tid={tenant_id}"
    return url


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Defender XDR Advanced Hunting deep link from KQL."
    )
    parser.add_argument("kql", nargs="?", help="KQL query string")
    parser.add_argument("--file", "-f", help="Read KQL from a file")
    parser.add_argument(
        "--md", action="store_true",
        help="Output as a markdown link: [Run in Advanced Hunting](url)"
    )
    parser.add_argument(
        "--tid", default=None,
        help="Tenant ID to append. If omitted, reads from config.json."
    )
    parser.add_argument(
        "--no-tid", action="store_true",
        help="Suppress tenant ID even if config.json has one."
    )
    args = parser.parse_args()

    # Read KQL from argument, file, or stdin
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            kql = f.read().strip()
    elif args.kql:
        kql = args.kql.strip()
    elif not sys.stdin.isatty():
        kql = sys.stdin.read().strip()
    else:
        parser.error("Provide KQL as an argument, via --file, or pipe to stdin.")
        return

    # Resolve tenant ID: explicit --tid > config.json > omit
    if args.no_tid:
        tenant_id = None
    elif args.tid:
        tenant_id = args.tid
    else:
        tenant_id = _load_tenant_id()

    url = kql_to_ah_url(kql, tenant_id=tenant_id)

    if args.md:
        print(f"[Run in Advanced Hunting]({url})")
    else:
        print(url)


if __name__ == "__main__":
    main()
