"""Shared test fixtures — synthetic samples built in-memory.

We never ship real malware. Each fixture crafts a *structurally valid* binary
carrying only benign marker strings that our detectors key on, so tests are
deterministic, offline, and safe.
"""
import struct

import pytest


def _align(n, a=0x200):
    return (n + a - 1) // a * a


def build_pe(section_data: list[tuple[bytes, bytes, int]], machine=0x8664) -> bytes:
    """Assemble a minimal PE32+ from (name, raw_bytes, characteristics) sections."""
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    opt_size = 0xE0
    coff = struct.pack("<H H I I I H H", machine, len(section_data),
                       0x62000000, 0, 0, opt_size, 0x22)
    opt = struct.pack("<H B B I I I I I", 0x20b, 14, 0, 0x400, 0, 0, 0x1000, 0)
    opt += struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200)
    opt += b"\x00" * (opt_size - len(opt))
    headers = mz + b"PE\x00\x00" + coff + opt
    raw_ptr = _align(len(headers) + 40 * len(section_data))
    sh = b""
    blobs = b""
    cur = raw_ptr
    vaddr = 0x1000
    for name, data, chars in section_data:
        rs = _align(len(data))
        sh += struct.pack("<8s I I I I I I H H I", name, len(data), vaddr, rs,
                          cur, 0, 0, 0, 0, chars)
        blobs += data + b"\x00" * (rs - len(data))
        cur += rs
        vaddr += _align(len(data), 0x1000)
    pre = headers + sh
    pre += b"\x00" * (raw_ptr - len(pre))
    return pre + blobs


@pytest.fixture
def go_ransomware_pe() -> bytes:
    import random
    behavior = (
        b"\xff Go build ID: \"abc\"\x00runtime.morestack\x00runtime.goexit\x00go1.21\x00"
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"vssadmin delete shadows /all /quiet\x00"
        b"Your files have been encrypted! decrypt to recover your files\x00"
        b"http://evil.example.onion/gate\x001A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\x00"
        b"CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00CryptEncrypt\x00"
    )
    packed = bytes(random.randrange(256) for _ in range(0x800))
    return build_pe([
        (b".text\x00\x00\x00", behavior + b"\x90" * 0x200, 0x60000020),
        (b".packed\x00", packed, 0xE0000020),
    ])


@pytest.fixture
def benign_pe() -> bytes:
    return build_pe([
        (b".text\x00\x00\x00", b"hello world benign program\x00" + b"\x90" * 0x300, 0x60000020),
        (b".data\x00\x00\x00", b"just some data here\x00" * 20, 0x40000040),
    ])
