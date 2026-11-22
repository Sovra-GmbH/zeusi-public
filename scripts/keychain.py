#!/usr/bin/env python3
"""Read/write macOS generic passwords without putting the secret in argv or stdout."""
from __future__ import annotations

import argparse
import os
import sys
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int32,
    c_uint32,
    c_void_p,
    cdll,
    create_string_buffer,
    memmove,
)
from ctypes.util import find_library

ERR_SUCCESS = 0
ERR_DUPLICATE = -25299
ERR_NOT_FOUND = -25300

def _refuse_in_tests() -> None:
    # Hermetic tests (src/keychain.ts realCredentialStoresBlocked): never touch the real Keychain
    # under `node --test` (NODE_TEST_CONTEXT) or with ZEUSI_TEST_NO_REAL_CREDS=1.
    if os.environ.get("ZEUSI_TEST_NO_REAL_CREDS") == "1" or os.environ.get("NODE_TEST_CONTEXT"):
        raise SystemExit("test mode (NODE_TEST_CONTEXT / ZEUSI_TEST_NO_REAL_CREDS=1): refusing to open the real Keychain")

def _sec():
    _refuse_in_tests()
    lib = find_library("Security")
    if not lib:
        raise SystemExit("Security framework not found")
    return cdll.LoadLibrary(lib)

def put(service: str, account: str, password: bytes) -> None:
    sec = _sec()
    sec.SecKeychainAddGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p, c_uint32, c_void_p, c_void_p
    ]
    sec.SecKeychainAddGenericPassword.restype = c_int32
    svc = service.encode()
    acct = account.encode()
    status = sec.SecKeychainAddGenericPassword(
        None, len(svc), svc, len(acct), acct, len(password), password, None
    )
    if status == ERR_SUCCESS:
        return
    if status != ERR_DUPLICATE:
        raise SystemExit(f"SecKeychainAddGenericPassword failed: {status}")
    # Update in place
    item = c_void_p()
    sec.SecKeychainFindGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p),
    ]
    sec.SecKeychainFindGenericPassword.restype = c_int32
    status = sec.SecKeychainFindGenericPassword(
        None, len(svc), svc, len(acct), acct, None, None, byref(item)
    )
    if status != ERR_SUCCESS:
        raise SystemExit(f"SecKeychainFindGenericPassword failed: {status}")
    sec.SecKeychainItemModifyContent.argtypes = [
        c_void_p, c_void_p, c_uint32, c_void_p
    ]
    sec.SecKeychainItemModifyContent.restype = c_int32
    status = sec.SecKeychainItemModifyContent(item, None, len(password), password)
    if status != ERR_SUCCESS:
        raise SystemExit(f"SecKeychainItemModifyContent failed: {status}")

def get(service: str, account: str) -> bytes:
    sec = _sec()
    sec.SecKeychainFindGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p),
    ]
    sec.SecKeychainFindGenericPassword.restype = c_int32
    length = c_uint32(0)
    data = c_void_p()
    svc = service.encode()
    acct = account.encode()
    status = sec.SecKeychainFindGenericPassword(
        None, len(svc), svc, len(acct), acct, byref(length), byref(data), None
    )
    if status == ERR_NOT_FOUND:
        raise SystemExit(f"not found: {service}")
    if status != ERR_SUCCESS:
        raise SystemExit(f"SecKeychainFindGenericPassword failed: {status}")
    buf = create_string_buffer(length.value)
    memmove(buf, data, length.value)
    sec.SecKeychainItemFreeContent.argtypes = [c_void_p, c_void_p]
    sec.SecKeychainItemFreeContent(None, data)
    return buf.raw

def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("put-stdin", "put-file", "len", "present", "emit"):
        sp = sub.add_parser(name)
        sp.add_argument("--service", required=True)
        sp.add_argument("--account", default=os.environ.get("USER", "owner"))
        if name == "put-file":
            sp.add_argument("--path", required=True)
    args = p.parse_args()
    if args.cmd == "put-stdin":
        data = sys.stdin.buffer.read()
        if data.endswith(b"\n") and b"\n" not in data[:-1]:
            data = data[:-1]
        if not data:
            raise SystemExit("empty stdin")
        put(args.service, args.account, data)
        print(f"stored service={args.service} account={args.account} length={len(data)}")
    elif args.cmd == "put-file":
        fd = os.open(args.path, os.O_RDONLY)
        try:
            data = os.read(fd, 1_000_000)
        finally:
            os.close(fd)
        if data.endswith(b"\n") and b"\n" not in data[:-1]:
            data = data[:-1]
        if not data:
            raise SystemExit("empty file")
        put(args.service, args.account, data)
        print(f"stored service={args.service} account={args.account} length={len(data)}")
    elif args.cmd == "len":
        data = get(args.service, args.account)
        print(f"present service={args.service} length={len(data)}")

    elif args.cmd == "emit":
        if os.environ.get("ZEUSI_KEYCHAIN_EMIT") != "1" or sys.stdout.isatty():
            raise SystemExit("emit requires ZEUSI_KEYCHAIN_EMIT=1 and a non-tty stdout")
        data = get(args.service, args.account)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    elif args.cmd == "present":
        try:
            data = get(args.service, args.account)
        except SystemExit as e:
            if "not found" in str(e):
                print(f"absent service={args.service}")
                return
            raise
        print(f"present service={args.service} length={len(data)}")

if __name__ == "__main__":
    main()
