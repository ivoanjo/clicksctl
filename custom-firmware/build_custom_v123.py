#!/usr/bin/env python3
"""Build custom CK-6100 V123 firmware from stock V122.

Reads iKeyboard_CK-6100_V122_300.bin from the current folder (downloading and
SHA-256 verifying it from upstream if missing) and writes
iKeyboard_CK-6100_V123_300_Custom.bin in the current folder.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import urllib.request
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
except ImportError:  # optional: only used to print disassembled instruction count
    Cs = None

HERE = Path(__file__).resolve().parent
SRC = HERE / "iKeyboard_CK-6100_V122_300.bin"
DST_BY_LAYOUT = {
    "us-intl": HERE / "iKeyboard_CK-6100_V123_300_Custom.bin",
    "pt": HERE / "iKeyboard_CK-6100_V123_300_Custom_PT.bin",
}
V122_URL = "https://xinyi1.clicks.tech/CK-6100/iKeyboard_CK-6100_V122_300.bin"
V122_SHA256 = "0e33d5132084d31258e1c300cc23e67e73d23179b9d57b03a8d62717a2b725c2"
BASE = 0x2000


def ensure_v122(src: Path, *, download: bool, force_download: bool) -> bytes:
    if src.exists() and not force_download:
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != V122_SHA256:
            raise SystemExit(
                f"SHA-256 mismatch for {src}:\n"
                f"  expected: {V122_SHA256}\n"
                f"  actual:   {digest}"
            )
        return data

    if not download:
        raise SystemExit(f"Missing {src} (re-run without --no-download to fetch upstream V122)")

    print(f"Downloading {V122_URL} ...")
    req = urllib.request.Request(V122_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != V122_SHA256:
        raise SystemExit(
            f"Upstream SHA-256 mismatch for {V122_URL}:\n"
            f"  expected: {V122_SHA256}\n"
            f"  actual:   {digest}"
        )
    src.write_bytes(data)
    print(f"Saved {src.name} ({len(data)} bytes, sha256={digest[:16]}...)")
    return data


def enc_jal(rd: int, off: int) -> bytes:
    assert -0x100000 <= off < 0x100000 and off % 2 == 0
    u = off & 0x1FFFFF
    w = ((u >> 20) & 1) << 31 | ((u >> 1) & 0x3FF) << 21 | ((u >> 11) & 1) << 20 | ((u >> 12) & 0xFF) << 12 | (rd << 7) | 0x6F
    return struct.pack("<I", w)


def enc_beq(rs1: int, rs2: int, off: int) -> bytes:
    assert -0x1000 <= off < 0x1000 and off % 2 == 0
    u = off & 0x1FFF
    w = ((u >> 12) & 1) << 31 | ((u >> 5) & 0x3F) << 25 | (rs2 << 20) | (rs1 << 15) | ((u >> 1) & 0xF) << 8 | ((u >> 11) & 1) << 7 | 0x63
    return struct.pack("<I", w)


def enc_bne(rs1: int, rs2: int, off: int) -> bytes:
    assert -0x1000 <= off < 0x1000 and off % 2 == 0
    u = off & 0x1FFF
    w = ((u >> 12) & 1) << 31 | ((u >> 5) & 0x3F) << 25 | (rs2 << 20) | (rs1 << 15) | (1 << 12) | ((u >> 1) & 0xF) << 8 | ((u >> 11) & 1) << 7 | 0x63
    return struct.pack("<I", w)


def enc_bgeu(rs1: int, rs2: int, off: int) -> bytes:
    assert -0x1000 <= off < 0x1000 and off % 2 == 0
    u = off & 0x1FFF
    w = ((u >> 12) & 1) << 31 | ((u >> 5) & 0x3F) << 25 | (rs2 << 20) | (rs1 << 15) | (7 << 12) | ((u >> 1) & 0xF) << 8 | ((u >> 11) & 1) << 7 | 0x63
    return struct.pack("<I", w)


def enc_addi(rd: int, rs1: int, imm: int) -> bytes:
    assert -2048 <= imm < 2048
    return struct.pack("<I", ((imm & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | 0x13)


def enc_lui(rd: int, imm20: int) -> bytes:
    return struct.pack("<I", ((imm20 & 0xFFFFF) << 12) | (rd << 7) | 0x37)


def enc_li(rd: int, val: int) -> bytes:
    lo = val & 0xFFF
    if lo >= 0x800:
        lo -= 0x1000
    hi = ((val - lo) >> 12) & 0xFFFFF
    return enc_lui(rd, hi) + enc_addi(rd, rd, lo)


class Asm:
    def __init__(self, base: int) -> None:
        self.base = base
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, callable]] = []

    def addr(self) -> int:
        return self.base + len(self.buf)

    def label(self, name: str) -> None:
        self.labels[name] = self.addr()

    def emit(self, data: bytes) -> None:
        self.buf.extend(data)

    def beq_label(self, rs1: int, rs2: int, target: str) -> None:
        pos = len(self.buf)
        self.buf.extend(b"\x00\x00\x00\x00")
        self.fixups.append((pos, target, lambda off: enc_beq(rs1, rs2, off)))

    def bne_label(self, rs1: int, rs2: int, target: str) -> None:
        pos = len(self.buf)
        self.buf.extend(b"\x00\x00\x00\x00")
        self.fixups.append((pos, target, lambda off: enc_bne(rs1, rs2, off)))

    def bgeu_label(self, rs1: int, rs2: int, target: str) -> None:
        pos = len(self.buf)
        self.buf.extend(b"\x00\x00\x00\x00")
        self.fixups.append((pos, target, lambda off: enc_bgeu(rs1, rs2, off)))

    def jal_label(self, rd: int, target: str) -> None:
        pos = len(self.buf)
        self.buf.extend(b"\x00\x00\x00\x00")
        self.fixups.append((pos, target, lambda off: enc_jal(rd, off)))

    def resolve(self) -> bytes:
        for pos, target, fn in self.fixups:
            off = self.labels[target] - (self.base + pos)
            self.buf[pos : pos + 4] = fn(off)
        return bytes(self.buf)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build custom CK-6100 V123 firmware from stock V122")
    ap.add_argument("--layout", choices=("us-intl", "pt"), default="us-intl", help="Target OS keyboard layout (default: us-intl)")
    ap.add_argument("--no-download", action="store_true", help="Fail if V122 is missing instead of downloading")
    ap.add_argument("--download", action="store_true", help="Force re-downloading upstream V122")
    args = ap.parse_args()
    is_pt = args.layout == "pt"
    dst = DST_BY_LAYOUT[args.layout]

    src_bytes = ensure_v122(SRC, download=not args.no_download, force_download=args.download)
    b = bytearray(src_bytes)
    a = Asm(BASE + len(b))  # 0x6bac

    # --- 1. Shift+Backspace -> Delete (hook at 0x31a8, return 0x31ac) ---
    assert b[0x11a8:0x11ac] == bytes.fromhex("1308a002")
    a.label("bksp_hook")
    a.emit(struct.pack("<I", 0x00064803))        # lbu a6, 0(a2)
    a.emit(struct.pack("<I", 0x00287893))        # andi a7, a6, 2
    a.beq_label(17, 0, "bksp_normal")            # beqz a7, bksp_normal
    a.emit(struct.pack("<I", 0xFFD87813))        # andi a6, a6, -3 (clear Left Shift)
    a.emit(struct.pack("<I", 0x01060023))        # sb a6, 0(a2)
    a.emit(struct.pack("<I", 0x04C00813))        # addi a6, zero, 0x4c (Delete)
    a.emit(enc_jal(0, 0x31AC - a.addr()))
    a.label("bksp_normal")
    a.emit(struct.pack("<I", 0x02A00813))        # addi a6, zero, 0x2a (Backspace)
    a.emit(enc_jal(0, 0x31AC - a.addr()))

    # --- 2. Shared helper: shift123_mux ---
    # Input: t0 (x5) = return address, a6 (x16) = normal | (alt<<8) | (shift_alt<<16) | (shift_flag<<24)
    # Preserves all regs except a6 and t0.
    a.label("shift123_mux")
    a.emit(enc_addi(2, 2, -8))                   # addi sp, sp, -8
    a.emit(struct.pack("<I", 0x00612023))        # sw t1, 0(sp)
    a.emit(struct.pack("<I", 0x00712223))        # sw t2, 4(sp)
    a.beq_label(15, 0, "mux_normal")             # beqz a5 (123 off), mux_normal
    a.emit(struct.pack("<I", 0x0005D303))        # lhu t1, 0(a1)
    a.emit(struct.pack("<I", 0x00837313))        # andi t1, t1, 8 (physical Shift)
    a.beq_label(6, 0, "mux_alt")                 # beqz t1, mux_alt
    # Shift + 123: set/clear Left Shift bit (0x02) from bit 24 and Right Alt (0x40) from bit 25 of a6
    a.emit(struct.pack("<I", 0x01885313))        # srli t1, a6, 24
    a.emit(struct.pack("<I", 0x00237393))        # andi t2, t1, 2
    a.emit(struct.pack("<I", 0x00539393))        # slli t2, t2, 5 (0x00 or 0x40)
    a.emit(struct.pack("<I", 0x00137313))        # andi t1, t1, 1
    a.emit(struct.pack("<I", 0x00131313))        # slli t1, t1, 1 (0x00 or 0x02)
    a.emit(struct.pack("<I", 0x00736333))        # or t1, t1, t2
    a.emit(struct.pack("<I", 0x00064383))        # lbu t2, 0(a2)
    a.emit(struct.pack("<I", 0xFFD3F393))        # andi t2, t2, -3
    a.emit(struct.pack("<I", 0x0063E3B3))        # or t2, t2, t1
    a.emit(struct.pack("<I", 0x00760023))        # sb t2, 0(a2)
    a.emit(struct.pack("<I", 0x01085813))        # srli a6, a6, 16
    a.emit(struct.pack("<I", 0x0FF87813))        # andi a6, a6, 0xff
    a.jal_label(0, "mux_done")
    a.label("mux_alt")
    if is_pt:
        # If bit 26 of a6 is set, assert Left Shift (0x02) on 123+<key> (for PT '/' on S and ';' on F)
        a.emit(struct.pack("<I", 0x01A85313))    # srli t1, a6, 26
        a.emit(struct.pack("<I", 0x00137313))    # andi t1, t1, 1
        a.beq_label(6, 0, "mux_alt_shift")       # beqz t1, mux_alt_shift
        a.emit(struct.pack("<I", 0x00064383))    # lbu t2, 0(a2)
        a.emit(struct.pack("<I", 0x0023E393))    # ori t2, t2, 2 (Left Shift)
        a.emit(struct.pack("<I", 0x00760023))    # sb t2, 0(a2)
        a.label("mux_alt_shift")
    a.emit(struct.pack("<I", 0x00885813))        # srli a6, a6, 8
    a.label("mux_normal")
    a.emit(struct.pack("<I", 0x0FF87813))        # andi a6, a6, 0xff
    a.label("mux_done")
    a.emit(struct.pack("<I", 0x00012303))        # lw t1, 0(sp)
    a.emit(struct.pack("<I", 0x00412383))        # lw t2, 4(sp)
    a.emit(enc_addi(2, 2, 8))                    # addi sp, sp, 8
    a.emit(struct.pack("<I", 0x00028067))        # jr t0

    # --- 3. Shift + 123 + key hooks (all using shift123_mux) ---
    # (name, patch_addr, orig_hex, ret_addr, normal, alt, shift_alt, flags)
    # flags: bit0=LeftShift on Shift+123, bit1=RightAlt on Shift+123, bit2=add LeftShift on 123 (pt only)
    if is_pt:
        key_specs = [
            ("a", 0x30DE, "1308d002", 0x3030, 0x04, 0x38, 0x38, 1),  # 123: - (/) | S+123: _ (Shift+/)
            ("q", 0x2EA8, "794891e3", 0x2EAE, 0x14, 0x1E, 0x64, 0),  # 123: 1     | S+123: < (ISO 0x64)
            ("w", 0x30B2, "7d48e390", 0x2E54, 0x1A, 0x1F, 0x64, 1),  # 123: 2     | S+123: > (Shift+0x64)
            ("s", 0x30C8, "13088003", 0x2FBA, 0x16, 0x24, 0x35, 4),  # 123: / (Shift+7) | S+123: \ (`)
            ("d", 0x30D4, "13083003", 0x2FE4, 0x07, 0x37, 0x24, 2),  # 123: : (Shift+.) | S+123: { (AltGr+7)
            ("f", 0x2FF4, "13083003", 0x2FFC, 0x09, 0x36, 0x27, 6),  # 123: ; (Shift+,) | S+123: } (AltGr+0)
            ("g", 0x3040, "13086002", 0x3048, 0x0A, 0x25, 0x25, 2),  # 123: ( (Shift+8) | S+123: [ (AltGr+8)
            ("h", 0x3062, "13087002", 0x306A, 0x0B, 0x26, 0x26, 2),  # 123: ) (Shift+9) | S+123: ] (AltGr+9)
            ("k", 0x3206, "13084003", 0x316E, 0x0E, 0x2D, 0x30, 0),  # 123: ' (non-dead -)| S+123: ´ (dead_acute ])
            ("l", 0x3210, "13084003", 0x3218, 0x0F, 0x1F, 0x31, 1),  # 123: " (Shift+2) | S+123: ^ (dead_circ Shift+\)
            ("z", 0x2CDC, "13082002", 0x2CE4, 0x1D, 0x22, 0x2F, 0),  # 123: % (Shift+5) | S+123: + ([)
            ("u", 0x2F0C, "13084002", 0x2F14, 0x18, 0x24, 0x20, 2),  # 123: 7     | S+123: £ (AltGr+3)
            ("i", 0x30BC, "13085002", 0x2F48, 0x0C, 0x25, 0x1C, 3),  # 123: 8     | S+123: ¥ (AltGr+Shift+Y)
            ("m", 0x2DA6, "13087003", 0x2DAE, 0x10, 0x37, 0x30, 1),  # 123: .     | S+123: ` (dead_grave Shift+])
            ("n", 0x2D84, "13086003", 0x2D8C, 0x11, 0x36, 0x31, 0),  # 123: ,     | S+123: ~ (dead_tilde \)
            ("x", 0x2CFE, "13084002", 0x2D06, 0x1B, 0x23, 0x27, 1),  # 123: & (Shift+6) | S+123: = (Shift+0)
            ("c", 0x2D20, "13085002", 0x2D28, 0x06, 0x2F, 0x33, 0),  # 123: * (Shift+[) | S+123: ç (;)
            ("v", 0x2D42, "13088003", 0x2D4A, 0x19, 0x2D, 0x33, 1),  # 123: ? (Shift+-) | S+123: Ç (Shift+;)
            ("b", 0x2D64, "794891e3", 0x2D6A, 0x05, 0x1E, 0x35, 1),  # 123: ! (Shift+1) | S+123: | (Shift+`)
        ]
    else:
        key_specs = [
            ("a", 0x30DE, "1308d002", 0x3030, 0x04, 0x2D, 0x2D, 1),  # _ (Shift + -)
            ("q", 0x2EA8, "794891e3", 0x2EAE, 0x14, 0x1E, 0x36, 1),  # < (Shift + ,)
            ("w", 0x30B2, "7d48e390", 0x2E54, 0x1A, 0x1F, 0x37, 1),  # > (Shift + .)
            ("s", 0x30C8, "13088003", 0x2FBA, 0x16, 0x38, 0x31, 0),  # \ (no Shift)
            ("d", 0x30D4, "13083003", 0x2FE4, 0x07, 0x33, 0x2F, 1),  # { (Shift + [)
            ("f", 0x2FF4, "13083003", 0x2FFC, 0x09, 0x33, 0x30, 1),  # } (Shift + ])
            ("g", 0x3040, "13086002", 0x3048, 0x0A, 0x26, 0x2F, 0),  # [ (no Shift)
            ("h", 0x3062, "13087002", 0x306A, 0x0B, 0x27, 0x30, 0),  # ] (no Shift)
            ("k", 0x3206, "13084003", 0x316E, 0x0E, 0x34, 0x34, 0),  # ´ (dead_acute ' on US-Intl, no Shift)
            ("l", 0x3210, "13084003", 0x3218, 0x0F, 0x34, 0x23, 1),  # ^ (Shift + 6)
            ("z", 0x2CDC, "13082002", 0x2CE4, 0x1D, 0x22, 0x2E, 1),  # + (Shift + =)
            ("u", 0x2F0C, "13084002", 0x2F14, 0x18, 0x24, 0x21, 3),  # £ (Right Alt + Shift + 4)
            ("i", 0x30BC, "13085002", 0x2F48, 0x0C, 0x25, 0x2D, 2),  # ¥ (Right Alt + -)
            ("m", 0x2DA6, "13087003", 0x2DAE, 0x10, 0x37, 0x35, 0),  # ` (no Shift)
            ("n", 0x2D84, "13086003", 0x2D8C, 0x11, 0x36, 0x35, 1),  # ~ (dead_tilde Shift+` on US-Intl)
            ("x", 0x2CFE, "13084002", 0x2D06, 0x1B, 0x24, 0x2E, 0),  # = (no Shift)
            ("c", 0x2D20, "13085002", 0x2D28, 0x06, 0x25, 0x36, 2),  # ç (Right Alt + ,)
            ("v", 0x2D42, "13088003", 0x2D4A, 0x19, 0x38, 0x36, 3),  # Ç (Right Alt + Shift + ,)
            ("b", 0x2D64, "794891e3", 0x2D6A, 0x05, 0x1E, 0x31, 1),  # | (Shift + \)
        ]

    hooks: list[tuple[int, str]] = [(0x31A8, "bksp_hook")]
    for name, paddr, ohex, raddr, nkc, akc, sakc, sflg in key_specs:
        off = paddr - BASE
        assert b[off : off + 4] == bytes.fromhex(ohex), f"mismatch at 0x{paddr:04x}: {b[off:off+4].hex()}"
        lbl = f"key_{name}"
        hooks.append((paddr, lbl))
        a.label(lbl)
        packed = nkc | (akc << 8) | (sakc << 16) | (sflg << 24)
        a.emit(enc_li(16, packed))               # li a6, packed
        a.jal_label(5, "shift123_mux")           # jal t0, shift123_mux
        a.emit(enc_jal(0, raddr - a.addr()))     # j raddr

    # --- 4. Special case for J (0x30e8 uses a7, currency on 123 at 0x30ec) ---
    assert b[0x10E8:0x10EC] == bytes.fromhex("b548d5db")
    hooks.append((0x30E8, "key_j"))
    a.label("key_j")
    a.beq_label(15, 0, "j_normal")               # beqz a5, j_normal
    a.emit(struct.pack("<I", 0x0005D883))        # lhu a7, 0(a1)
    a.emit(struct.pack("<I", 0x0088F893))        # andi a7, a7, 8 (physical Shift)
    a.bne_label(17, 0, "j_shift123")             # bnez a7, j_shift123
    a.emit(enc_jal(0, 0x30EC - a.addr()))        # j 0x30ec (currency)
    a.label("j_shift123")
    a.emit(struct.pack("<I", 0x00064883))        # lbu a7, 0(a2)
    a.emit(struct.pack("<I", 0xFFD8F893))        # andi a7, a7, -3 (clear Left Shift 0x02)
    a.emit(struct.pack("<I", 0x0408E893))        # ori a7, a7, 0x40 (Right Alt / AltGr)
    a.emit(struct.pack("<I", 0x01160023))        # sb a7, 0(a2)
    a.emit(enc_addi(17, 0, 0x08 if is_pt else 0x22))  # AltGr+E (pt) or AltGr+5 (us-intl) = €
    a.emit(enc_jal(0, 0x309E - a.addr()))        # j 0x309e
    a.label("j_normal")
    a.emit(struct.pack("<I", 0x00D00893))        # addi a7, zero, 0x0d ('j')
    a.emit(enc_jal(0, 0x309E - a.addr()))        # j 0x309e

    if is_pt:
        # --- 4a. @ key (0x30a6) -> Right Alt + 2 on Portuguese (clear Left Shift, set Right Alt 0x40) ---
        # Guard on a5 == 0 because 0x2dde (123+@ -> '#') also branches to 0x30a6 with a5 != 0 and a7 = 0x20.
        assert b[0x10A6:0x10AA] == bytes.fromhex("23001801")
        hooks.append((0x30A6, "at_hook"))
        a.label("at_hook")
        a.bne_label(15, 0, "at_store")           # bnez a5, at_store (123+@ -> keep Shift+0x20 = '#')
        a.emit(struct.pack("<I", 0x00064883))    # lbu a7, 0(a2)
        a.emit(struct.pack("<I", 0xFFD8F893))    # andi a7, a7, -3 (clear Left Shift 0x02)
        a.emit(struct.pack("<I", 0x0408E893))    # ori a7, a7, 0x40 (Right Alt / AltGr)
        a.emit(struct.pack("<I", 0x01160023))    # sb a7, 0(a2)
        a.emit(struct.pack("<I", 0x01F00893))    # addi a7, zero, 0x1f ('2')
        a.label("at_store")
        a.emit(bytes.fromhex("23001801"))        # sb a7, 0(a6)
        a.emit(enc_jal(0, 0x2DEC - a.addr()))    # j 0x2dec

    # --- 4b. Globe + Cmd -> Media Play/Pause (bit 3 = 0x08 in consumer byte 6(a2)) ---
    assert b[0x11BC:0x11C0] == bytes.fromhex("858b89c7")
    hooks.append((0x31BC, "globe_cmd_hook"))
    a.label("globe_cmd_hook")
    a.emit(struct.pack("<I", 0x0037F813))        # andi a6, a5, 3
    a.emit(struct.pack("<I", 0x00300893))        # addi a7, zero, 3
    a.bne_label(16, 17, "globe_cmd_normal")      # bne a6, a7, globe_cmd_normal
    a.emit(struct.pack("<I", 0x00664803))        # lbu a6, 6(a2)
    a.emit(struct.pack("<I", 0x00886813))        # ori a6, a6, 8
    a.emit(struct.pack("<I", 0x01060323))        # sb a6, 6(a2)
    a.emit(enc_jal(0, 0x31D6 - a.addr()))        # j 0x31d6
    a.label("globe_cmd_normal")
    a.emit(struct.pack("<H", 0x8B85))            # c.andi a5, 1
    a.beq_label(15, 0, "globe_cmd_skip_globe")   # beqz a5, 0x31c8
    a.emit(enc_jal(0, 0x31C0 - a.addr()))        # j 0x31c0
    a.label("globe_cmd_skip_globe")
    a.emit(enc_jal(0, 0x31C8 - a.addr()))        # j 0x31c8

    # --- 4c. USB EP1 TX busy key-report retry (hardware UEP1_TX_CTRL check) ---
    # 1) Hook 0x24bc (bne a3, a1, 0xce): allow scan in active/retry states 1..61 (forcing a3=1 for 0x2570)
    assert b[0x04BC:0x04C0] == bytes.fromhex("6397b60c")
    hooks.append((0x24BC, "scan_state_hook"))
    a.label("scan_state_hook")
    a.emit(struct.pack("<I", 0xFFF68793))        # addi a5, a3, -1
    a.emit(enc_addi(13, 0, 61))                  # addi a3, zero, 61 (max active/retry state = 60 * 2ms = 120ms)
    a.bgeu_label(15, 13, "scan_state_idle")      # bgeu a5, a3, scan_state_idle (state == 0 or >= 62)
    a.emit(struct.pack("<I", 0x00100693))        # addi a3, zero, 1 (keep a3=1 for 0x2570 sll)
    a.emit(enc_jal(0, 0x24C0 - a.addr()))        # j 0x24c0
    a.label("scan_state_idle")
    a.emit(enc_jal(0, 0x258A - a.addr()))        # j 0x258a

    # 2) Hook 0x25a8 (c.lw a5, 0x20(s0); c.beqz a5, 8): if UEP1_TX_CTRL[1:0] == 0 (ACK / previous HID report
    #    still unread by host), defer callback & snapshot update up to 60 scan ticks (120 ms) so EP1 TX isn't overwritten.
    assert b[0x05A8:0x05AC] == bytes.fromhex("1c5081c7")
    hooks.append((0x25A8, "scan_cb_hook"))
    a.label("scan_cb_hook")
    a.emit(struct.pack("<I", 0x400237B7))        # lui a5, 0x40023 (USBFS base)
    a.emit(struct.pack("<I", 0x4267D783))        # lhu a5, 0x426(a5) (UEP1_TX_CTRL)
    a.emit(struct.pack("<I", 0x0037F793))        # andi a5, a5, 3
    a.bne_label(15, 0, "scan_cb_ready")          # bnez a5, scan_cb_ready (NAK/idle -> ready)
    a.emit(struct.pack("<I", 0x00044703))        # lbu a4, 0(s0)
    a.emit(enc_addi(15, 0, 61))                  # addi a5, zero, 61 (60 retries * 2ms = 120ms)
    a.bgeu_label(14, 15, "scan_cb_ready")        # bgeu a4, a5, scan_cb_ready (give up if host stopped polling)
    a.emit(struct.pack("<I", 0x00170713))        # addi a4, a4, 1
    a.emit(struct.pack("<I", 0x00E40023))        # sb a4, 0(s0)
    a.emit(enc_jal(0, 0x251E - a.addr()))        # j 0x251e (epilogue without updating snapshot)
    a.label("scan_cb_ready")
    a.emit(struct.pack("<I", 0x00100713))        # addi a4, zero, 1
    a.emit(struct.pack("<I", 0x00E40023))        # sb a4, 0(s0) (reset state = 1)
    a.emit(struct.pack("<I", 0x02042783))        # lw a5, 0x20(s0)
    a.beq_label(15, 0, "scan_cb_copy")           # beqz a5, scan_cb_copy
    a.emit(struct.pack("<I", 0x01C42503))        # lw a0, 0x1c(s0)
    a.emit(struct.pack("<I", 0x00400613))        # addi a2, zero, 4
    a.emit(struct.pack("<I", 0x000780E7))        # jalr ra, a5, 0
    a.label("scan_cb_copy")
    a.emit(enc_jal(0, 0x25B2 - a.addr()))        # j 0x25b2 (update snapshot & finish)

    # --- 4d. USB Suspend + Remote Wakeup precedence over accs_stop (CA-2200 V1.1.5 fix) ---
    # 0) Hook 0x23d8 (c.lw a5, 8(s0); c.beqz a5, 0x20): when accs_stop=ON and USB is already suspended (s2 != 0),
    #    enter STOP mode (0x23fa) immediately instead of spinning at 48 MHz until the idle timer expires.
    assert b[0x03D8:0x03DC] == bytes.fromhex("1c4485c3")
    hooks.append((0x23D8, "sleep_entry_hook"))
    a.label("sleep_entry_hook")
    a.bne_label(18, 0, "sleep_enter_stop")       # bnez s2, sleep_enter_stop
    a.emit(struct.pack("<I", 0x00842783))        # lw a5, 8(s0)
    a.beq_label(15, 0, "sleep_enter_stop")       # beqz a5, sleep_enter_stop
    a.emit(enc_jal(0, 0x23DC - a.addr()))        # j 0x23dc (idle > 0 and not suspended -> skip STOP)
    a.label("sleep_enter_stop")
    a.emit(enc_jal(0, 0x23FA - a.addr()))        # j 0x23fa (enter STOP mode)

    # 1) Hook 0x2418 (lbu a5, 0x174(s0)): if USB already suspended (s2 != 0), skip 0x41ac USB disconnect.
    assert b[0x0418:0x041C] == bytes.fromhex("83474417")
    hooks.append((0x2418, "sleep_suspend_hook"))
    a.label("sleep_suspend_hook")
    a.bne_label(18, 0, "sleep_skip_disc")        # bnez s2, sleep_skip_disc
    a.emit(bytes.fromhex("83474417"))            # lbu a5, 0x174(s0)
    a.emit(enc_jal(0, 0x241C - a.addr()))        # j 0x241c
    a.label("sleep_skip_disc")
    a.emit(enc_jal(0, 0x2424 - a.addr()))        # j 0x2424 (enter STOP without disconnecting USB)

    # 2) Hook 0x2432 (lbu a5, 0x174(s0)): if USB was suspended (s2 != 0), skip 0x4454 USB reconnect -> Remote Wakeup.
    assert b[0x0432:0x0436] == bytes.fromhex("83474417")
    hooks.append((0x2432, "wake_suspend_hook"))
    a.label("wake_suspend_hook")
    a.bne_label(18, 0, "wake_remote")            # bnez s2, wake_remote
    a.emit(bytes.fromhex("83474417"))            # lbu a5, 0x174(s0)
    a.emit(enc_jal(0, 0x2436 - a.addr()))        # j 0x2436
    a.label("wake_remote")
    a.emit(enc_jal(0, 0x245A - a.addr()))        # j 0x245a (checks s1 -> 0x41ea Remote Wakeup)

    tramp_bytes = a.resolve()
    for paddr, lbl in hooks:
        off = paddr - BASE
        b[off : off + 4] = enc_jal(0, a.labels[lbl] - paddr)
    b.extend(tramp_bytes)

    # --- 5. Patch & relocate HID report descriptor to 0x6e80 ---
    # 1) Widen modifier range 0xE0..0xE3 (4 bits + 4-bit pad) -> 0xE0..0xE7 (all 8 bits, incl. Right Alt 0x40)
    # 2) App-grid (0x01AE) -> AC Home (0x0223), Mic (0x00CF) -> AC Back (0x0224), add Play/Pause (0x00CD) as bit 3
    orig_hd = bytes(b[0x4854 : 0x4854 + 97])
    assert orig_hd.startswith(bytes.fromhex("05010906a101"))
    assert orig_hd[32:48] == bytes.fromhex("19e029e3750195048102750495018103")
    assert orig_hd[76:] == bytes.fromhex("0aae010a9d0209cf750195038102750d95018103c0")
    hid_desc = (
        orig_hd[:32]
        + bytes.fromhex("19e029e7750195088102")
        + orig_hd[48:76]
        + bytes.fromhex("0a23020a9d020a240209cd750195048102750c95018103c0")
    )
    assert len(hid_desc) == 94  # 0x5E

    reloc_addr = 0x6EC0 if is_pt else 0x6E80
    pad = reloc_addr - (BASE + len(b))
    assert pad >= 0, f"trampolines ran past 0x{reloc_addr:04x}"
    b.extend(b"\xff" * pad)
    b.extend(hid_desc)

    # Update wDescriptorLength in USB Config Descriptor (0x47ed..0x47ee) and GET_DESCRIPTOR (0x3cce)
    assert b[0x47E6:0x47EF] == bytes.fromhex("092101010001226100")
    b[0x47ED:0x47EF] = struct.pack("<H", len(hid_desc))
    assert b[0x1CCE:0x1CD2] == bytes.fromhex("93071006")
    b[0x1CCE:0x1CD2] = enc_addi(15, 0, len(hid_desc))

    # Raise HID Interrupt EP 0x81 / 0x01 bInterval from 1 ms (1000 Hz) to 8 ms (125 Hz, matching 8 ms matrix scan)
    assert b[0x47EF:0x47FD] == bytes.fromhex("0705810340000107050103400001")
    b[0x47F5] = 8
    b[0x47FC] = 8

    # Patch GET_DESCRIPTOR HID report pointer at 0x3ce4..0x3ce9:
    #   0x3ce4: 1d 65       c.lui a0, 7
    #   0x3ce6: 13 05 45 85 addi  a0, a0, -0x7ac  (0x6854) -> -0x180 (0x6e80)
    assert b[0x1CE4:0x1CEA] == bytes.fromhex("1d6513054585")
    b[0x1CE6:0x1CEA] = enc_addi(10, 10, reloc_addr - 0x7000)

    # Bump version 1.22 -> 1.23
    b[0x1C28:0x1C2C] = b"\x93\x07\x30\x02"
    b[0x4840:0x4842] = b"\x23\x01"
    b[0x4A95:0x4A9A] = b"1.2.3"

    assert len(b) <= 0x69FF, f"image exceeds bootloader max 0x69ff: {len(b)}"

    extra = ""
    if Cs is not None:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
        insns = list(md.disasm(tramp_bytes, BASE + len(src_bytes)))
        assert sum(i.size for i in insns) == len(tramp_bytes), "trampoline decode gap"
        orig_addrs = (
            {i.address for i in md.disasm(src_bytes[0x35E:0x5C6], 0x235E)}
            | {i.address for i in md.disasm(src_bytes[0xC00:0x1400], 0x2C00)}
        )
        check_addrs = [
            0x23D8, 0x23DC, 0x23FA,
            0x2418, 0x241C, 0x2424, 0x2432, 0x2436, 0x245A,
            0x24BC, 0x24C0, 0x258A, 0x25A8, 0x25B2, 0x251E,
            0x31A8, 0x31AC, 0x30E8, 0x30EC, 0x309E, 0x31BC, 0x31C0, 0x31C8, 0x31D6,
        ]
        if is_pt:
            check_addrs.extend((0x30A6, 0x2DEC))
        for _, paddr, _, raddr, *_ in key_specs:
            check_addrs.extend((paddr, raddr))
        for addr in check_addrs:
            assert addr in orig_addrs, f"0x{addr:04x} is not a valid instruction boundary in V122"
        extra = f", {len(insns)} insns, boundaries OK"

    dst.write_bytes(b)
    print(f"Built {dst} [{args.layout}] ({len(b)} bytes, +{len(tramp_bytes)} B trampolines{extra})")
    print("sha256:", hashlib.sha256(b).hexdigest())


if __name__ == "__main__":
    main()
