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
DST = HERE / "iKeyboard_CK-6100_V123_300_Custom.bin"
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
    ap.add_argument("--no-download", action="store_true", help="Fail if V122 is missing instead of downloading")
    ap.add_argument("--download", action="store_true", help="Force re-downloading upstream V122")
    args = ap.parse_args()

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
    a.emit(struct.pack("<I", 0x00885813))        # srli a6, a6, 8
    a.label("mux_normal")
    a.emit(struct.pack("<I", 0x0FF87813))        # andi a6, a6, 0xff
    a.label("mux_done")
    a.emit(struct.pack("<I", 0x00012303))        # lw t1, 0(sp)
    a.emit(struct.pack("<I", 0x00412383))        # lw t2, 4(sp)
    a.emit(enc_addi(2, 2, 8))                    # addi sp, sp, 8
    a.emit(struct.pack("<I", 0x00028067))        # jr t0

    # --- 3. Shift + 123 + key hooks (all using shift123_mux) ---
    # (name, patch_addr, orig_hex, ret_addr, normal, alt, shift_alt, shift_flag)
    key_specs = [
        ("a", 0x30DE, "1308d002", 0x3030, 0x04, 0x2D, 0x2D, 1),  # _ (Shift + -)
        ("q", 0x2EA8, "794891e3", 0x2EAE, 0x14, 0x1E, 0x36, 1),  # < (Shift + ,)
        ("w", 0x30B2, "7d48e390", 0x2E54, 0x1A, 0x1F, 0x37, 1),  # > (Shift + .)
        ("s", 0x30C8, "13088003", 0x2FB8, 0x16, 0x38, 0x31, 0),  # \ (no Shift)
        ("d", 0x30D4, "13083003", 0x2FE4, 0x07, 0x33, 0x2F, 1),  # { (Shift + [)
        ("f", 0x2FF4, "13083003", 0x2FFC, 0x09, 0x33, 0x30, 1),  # } (Shift + ])
        ("g", 0x3040, "13086002", 0x3048, 0x0A, 0x26, 0x2F, 0),  # [ (no Shift)
        ("h", 0x3062, "13087002", 0x306A, 0x0B, 0x27, 0x30, 0),  # ] (no Shift)
        ("k", 0x3206, "13084003", 0x316E, 0x0E, 0x34, 0x35, 0),  # ` (no Shift)
        ("l", 0x3210, "13084003", 0x3218, 0x0F, 0x34, 0x23, 1),  # ^ (Shift + 6)
        ("z", 0x2CDC, "13082002", 0x2CE4, 0x1D, 0x22, 0x2E, 1),  # + (Shift + =)
        ("u", 0x2F0C, "13084002", 0x2F14, 0x18, 0x24, 0x21, 3),  # £ (Right Alt + Shift + 4)
        ("i", 0x30BC, "13085002", 0x2F48, 0x0C, 0x25, 0x2D, 2),  # ¥ (Right Alt + -)
        ("m", 0x2DA6, "13087003", 0x2DAE, 0x10, 0x37, 0x34, 0),  # ´ (dead_acute ' on US-Intl, no Shift)
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
    a.emit(struct.pack("<I", 0x02200893))        # addi a7, zero, 0x22 ('5' -> AltGr+5 = € on Linux us-intl/altgr-intl)
    a.emit(enc_jal(0, 0x309E - a.addr()))        # j 0x309e
    a.label("j_normal")
    a.emit(struct.pack("<I", 0x00D00893))        # addi a7, zero, 0x0d ('j')
    a.emit(enc_jal(0, 0x309E - a.addr()))        # j 0x309e

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

    tramp_bytes = a.resolve()
    for paddr, lbl in hooks:
        off = paddr - BASE
        b[off : off + 4] = enc_jal(0, a.labels[lbl] - paddr)
    b.extend(tramp_bytes)

    # --- 5. Patch & relocate HID report descriptor to 0x6d20 ---
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

    reloc_addr = 0x6E00
    pad = reloc_addr - (BASE + len(b))
    assert pad >= 0, f"trampolines ran past 0x{reloc_addr:04x}"
    b.extend(b"\xff" * pad)
    b.extend(hid_desc)

    # Update wDescriptorLength in USB Config Descriptor (0x47ed..0x47ee) and GET_DESCRIPTOR (0x3cce)
    assert b[0x47E6:0x47EF] == bytes.fromhex("092101010001226100")
    b[0x47ED:0x47EF] = struct.pack("<H", len(hid_desc))
    assert b[0x1CCE:0x1CD2] == bytes.fromhex("93071006")
    b[0x1CCE:0x1CD2] = enc_addi(15, 0, len(hid_desc))

    # Patch GET_DESCRIPTOR HID report pointer at 0x3ce4..0x3ce9:
    #   0x3ce4: 1d 65       c.lui a0, 7
    #   0x3ce6: 13 05 45 85 addi  a0, a0, -0x7ac  (0x6854) -> -0x2e0 (0x6d20)
    assert b[0x1CE4:0x1CEA] == bytes.fromhex("1d6513054585")
    b[0x1CE6:0x1CEA] = enc_addi(10, 10, reloc_addr - 0x7000)

    # Bump version 1.22 -> 1.23
    b[0x1C28:0x1C2C] = b"\x93\x07\x30\x02"
    b[0x4840:0x4842] = b"\x23\x01"
    b[0x4A95:0x4A9A] = b"1.2.3"

    DST.write_bytes(b)
    extra = ""
    if Cs is not None:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
        insns = list(md.disasm(tramp_bytes, BASE + len(src_bytes)))
        extra = f", {len(insns)} insns"
    print(f"Built {DST} ({len(b)} bytes, +{len(tramp_bytes)} B trampolines{extra})")
    print("sha256:", hashlib.sha256(b).hexdigest())


if __name__ == "__main__":
    main()
