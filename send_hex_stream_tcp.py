#!/usr/bin/env python3
"""
send_hex_persistent_tcp.py

Opens a single TCP connection to host:port, reads an input file line-by-line,
parses bracketed hex lists like:
  [01, 7F, 02, 47, 31, ...]
and sends each parsed byte payload over the same TCP connection at a configurable
rate (default 1 packet per second). The script does not wait for any response.

Behavior:
 - One TCP connection is established at start (or on first send).
 - If the connection drops, the script will attempt to reconnect and resume sending.
 - Malformed lines are logged and skipped.
 - Empty or non-matching lines are ignored.
"""

from __future__ import annotations
import argparse
import re
import socket
import sys
import time
from typing import Optional, List

HEX_LINE_RE = re.compile(r'\[([0-9A-Fa-fxX,\s]+)\]')

def parse_hex_list_from_text(s: str) -> Optional[bytes]:
    """
    Extract the first bracketed hex list from the string and return it as bytes.
    Accepts tokens like: 01, 7F, 0x02, a, A. Returns None if no bracketed list found.
    Raises ValueError for invalid tokens.
    """
    m = HEX_LINE_RE.search(s)
    if not m:
        return None
    inner = m.group(1)
    tokens = re.split(r'[,\s]+', inner.strip())
    out: List[int] = []
    for tok in tokens:
        if not tok:
            continue
        tok_clean = tok.lower()
        if tok_clean.startswith('0x'):
            tok_clean = tok_clean[2:]
        if not re.fullmatch(r'[0-9a-fA-F]+', tok_clean):
            raise ValueError(f"Invalid hex token: {tok!r}")
        val = int(tok_clean, 16)
        if val < 0 or val > 0xFF:
            raise ValueError(f"Hex value out of byte range: {tok!r}")
        out.append(val)
    return bytes(out)

class PersistentSender:
    """
    Maintains a single TCP connection and sends payloads over it.
    Reconnects on failure with a simple retry loop.
    """
    def __init__(self, host: str, port: int, connect_timeout: float = 5.0, max_retries: int = 5, retry_delay: float = 1.0):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.sock: Optional[socket.socket] = None

    def ensure_connected(self) -> None:
        """Ensure there is an open socket. Attempt to connect if needed."""
        if self.sock is not None:
            return
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                self.sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
                # optional: set a short send timeout so sendall doesn't block forever
                self.sock.settimeout(self.connect_timeout)
                return
            except Exception as e:
                last_exc = e
                time.sleep(self.retry_delay)
        raise ConnectionError(f"Failed to connect to {self.host}:{self.port} after {self.max_retries} attempts: {last_exc}")

    def send(self, payload: bytes) -> None:
        """
        Send payload over the persistent connection. On failure attempt to reconnect once
        then resend. If reconnect fails the exception propagates.
        """
        try:
            self.ensure_connected()
            # sendall might raise on broken pipe / network error
            self.sock.sendall(payload)
        except Exception as first_exc:
            # attempt reconnect and resend once
            try:
                self.close()
                self.ensure_connected()
                self.sock.sendall(payload)
            except Exception as second_exc:
                # give up and re-raise the second exception for caller to handle/log
                raise second_exc from first_exc

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

def main() -> None:
    p = argparse.ArgumentParser(description="Send bracketed-hex lines over a persistent TCP connection at a fixed rate.")
    p.add_argument('file', help='Input file path')
    p.add_argument('--host', required=True, help='TCP server host or IP')
    p.add_argument('--port', required=True, type=int, help='TCP server port')
    p.add_argument('--rate', type=float, default=1.0, help='Packets per second (default 1.0)')
    p.add_argument('--connect-timeout', type=float, default=5.0, help='Socket connect/send timeout seconds (default 5)')
    p.add_argument('--retries', type=int, default=5, help='Connect retries on failure (default 5)')
    p.add_argument('--retry-delay', type=float, default=1.0, help='Seconds between reconnect attempts (default 1.0)')
    args = p.parse_args()

    if args.rate <= 0:
        print("Error: rate must be > 0", file=sys.stderr)
        sys.exit(2)
    delay = 1.0 / args.rate

    sender = PersistentSender(args.host, args.port, connect_timeout=args.connect_timeout,
                              max_retries=args.retries, retry_delay=args.retry_delay)

    try:
        f = open(args.file, 'r', encoding='utf-8', errors='replace')
    except Exception as e:
        print(f"Failed to open file: {e}", file=sys.stderr)
        sys.exit(3)

    sent_count = 0
    try:
        # attempt initial connection now to fail-fast if desired. If initial connect fails,
        # PersistentSender will retry on first send as well.
        try:
            sender.ensure_connected()
            print(f"Connected to {args.host}:{args.port}")
        except Exception as e:
            # log and continue; will retry on send
            print(f"Warning: initial connect failed: {e}. Will retry on first send.", file=sys.stderr)

        for lineno, line in enumerate(f, start=1):
            raw = line.rstrip('\n')
            if not raw.strip():
                continue
            try:
                payload = parse_hex_list_from_text(raw)
                if payload is None:
                    continue
            except Exception as err:
                print(f"[line {lineno}] parse error: {err}", file=sys.stderr)
                continue

            try:
                sender.send(payload)
                sent_count += 1
                print(f"[line {lineno}] sent {len(payload)} bytes")
            except Exception as e:
                print(f"[line {lineno}] send error: {e}", file=sys.stderr)
                # attempt to continue to next lines (sender will try reconnect on next send)
            # rate control
            time.sleep(delay)

        print(f"Done. Sent {sent_count} payloads.")
    finally:
        try:
            sender.close()
        finally:
            f.close()

if __name__ == "__main__":
    main()
