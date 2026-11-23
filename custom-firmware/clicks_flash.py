#!/usr/bin/env python3
"""CK-6100 firmware flasher over USB/iAP2 (reuses ../clicksctl).

SAFETY:
- Dry-run by default; sends ZERO A0-A3 packets unless --flash --confirm CK-6100 is passed.
- Verifies device reports model=CK-6100 and hw=3.0.0 before flashing.
- Enforces image size <= 0x69FF (27,135 bytes, bootloader copier limit) and verifies SHA-256 when --target is used.
- Guards against low idle intervals (< 30 s) unless --allow-low-idle is passed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import struct
import sys
import time
from pathlib import Path

_CLICKSCTL_PATH = Path(__file__).resolve().parent.parent / "clicksctl"
_LOADER = importlib.machinery.SourceFileLoader("clicksctl", str(_CLICKSCTL_PATH))
_SPEC = importlib.util.spec_from_loader("clicksctl", _LOADER)
assert _SPEC is not None and _SPEC.loader is not None
_clicksctl = importlib.util.module_from_spec(_SPEC)
sys.modules["clicksctl"] = _clicksctl
_SPEC.loader.exec_module(_clicksctl)

CMD_GET_IDLE_INTERVAL = _clicksctl.CMD_GET_IDLE_INTERVAL
CMD_GET_VERSION = _clicksctl.CMD_GET_VERSION
ClicksSession = _clicksctl.ClicksSession
encode_getter = _clicksctl.encode_getter

HERE = Path(__file__).resolve().parent

CK6100_IMAGES = {
    "1.23-Custom": (
        HERE / "iKeyboard_CK-6100_V123_300_Custom.bin",
        "b263f39e7a4e526b58f8752b0fcfe145320643e9a81665db012edaa5bf1984c5",
    ),
    "1.22": (
        HERE / "iKeyboard_CK-6100_V122_300.bin",
        "0e33d5132084d31258e1c300cc23e67e73d23179b9d57b03a8d62717a2b725c2",
    ),
    "1.20": (
        HERE / "iKeyboard_CK-6100_V120_300.bin",
        "597f5f82fa699eb1428fec675c178c4dd66348244b513c22385bd41462481f65",
    ),
}

MAX_IMAGE_SIZE = 0x69FF
MIN_SAFE_IDLE_S = 30
CHUNK_SIZE = 32

CMD_FW_BEGIN = 0xA1
CMD_FW_DATA = 0xA2
CMD_FW_COMMIT = 0xA3
CMD_FW_REBOOT = 0xA0


def pkt_begin(size: int) -> bytes:
    return bytes((0x06, CMD_FW_BEGIN)) + struct.pack(">I", size)


def pkt_data(offset: int, chunk: bytes) -> bytes:
    if not 1 <= len(chunk) <= CHUNK_SIZE:
        raise ValueError(f"chunk must be 1..{CHUNK_SIZE} bytes")
    return bytes((len(chunk) + 6, CMD_FW_DATA)) + struct.pack(">I", offset) + chunk


def pkt_commit(size: int) -> bytes:
    return bytes((0x06, CMD_FW_COMMIT)) + struct.pack(">I", size)


def pkt_reboot() -> bytes:
    return bytes((0x02, CMD_FW_REBOOT))


def load_image(path: Path, expected_sha256: str | None) -> tuple[bytes, str]:
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise SystemExit(
            f"Refusing image {path}: SHA-256 mismatch\n"
            f"  expected: {expected_sha256}\n"
            f"  actual:   {digest}"
        )
    if not 0 < len(image) <= MAX_IMAGE_SIZE:
        raise SystemExit(f"Invalid image size {len(image)} (max {MAX_IMAGE_SIZE})")
    return image, digest


def main() -> int:
    ap = argparse.ArgumentParser(description="CK-6100 firmware flasher (dry-run by default)")
    ap.add_argument("--serial", default=None, help="Target USB serial (required if multiple devices are attached)")
    ap.add_argument("--target", choices=sorted(CK6100_IMAGES), help="Known firmware target (verifies SHA-256)")
    ap.add_argument("--image", type=Path, help="Path to firmware .bin")
    ap.add_argument("--allow-downgrade", action="store_true", help="Allow flashing 1.20 onto 1.22")
    ap.add_argument("--allow-low-idle", action="store_true", help=f"Allow flashing when device idle < {MIN_SAFE_IDLE_S} s")
    ap.add_argument("--plan-only", action="store_true", help="Verify image & print packet plan offline (no USB)")
    ap.add_argument("--flash", action="store_true", help="Actually send A1/A2/A3/A0 (requires --confirm CK-6100)")
    ap.add_argument("--confirm", default="", help="Must be CK-6100 when --flash is used")
    ap.add_argument("--no-reboot", action="store_true", help="Stage A1/A2/A3 only without sending A0 reboot")
    args = ap.parse_args()

    if args.target is None and args.image is None:
        args.target = "1.23-Custom"

    expected_sha: str | None = None
    if args.target is not None:
        default_path, expected_sha = CK6100_IMAGES[args.target]
        img_path = args.image or default_path
    else:
        assert args.image is not None
        img_path = args.image

    image, digest = load_image(img_path, expected_sha)
    chunks = (len(image) + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"Image OK: {img_path.name} ({len(image)} bytes, {chunks} A2 chunks, sha256={digest[:16]}...)")

    if args.plan_only:
        print(f"  A1 begin:  {pkt_begin(len(image)).hex(' ')}")
        print(f"  A2 chunk0: {pkt_data(0, image[:CHUNK_SIZE]).hex(' ')}")
        last_off = (chunks - 1) * CHUNK_SIZE
        print(f"  A2 last:   {pkt_data(last_off, image[last_off:]).hex(' ')}")
        print(f"  A3 commit: {pkt_commit(len(image)).hex(' ')}")
        print(f"  A0 reboot: {pkt_reboot().hex(' ')}")
        return 0

    if args.flash and args.confirm != "CK-6100":
        raise SystemExit("Refusing --flash without --confirm CK-6100")

    with ClicksSession(args.serial, timeout_ms=2000) as sess:
        model = sess.ident.get(1, b"").rstrip(b"\x00").decode("ascii", "replace")
        hw_str = sess.ident.get(5, b"").rstrip(b"\x00").decode("ascii", "replace")
        fw_str = sess.ident.get(4, b"").rstrip(b"\x00").decode("ascii", "replace")
        ver = sess.transact(encode_getter(CMD_GET_VERSION), CMD_GET_VERSION).payload
        cur_fw = f"{ver[2]}.{ver[3]:02x}"
        idle_s = struct.unpack(">H", sess.transact(encode_getter(CMD_GET_IDLE_INTERVAL), CMD_GET_IDLE_INTERVAL).payload)[0]
        print(f"Device: serial={sess.actual_serial} model={model} hw={hw_str} fw={fw_str} idle={idle_s}s raw_ver={ver.hex(' ')}")

        if model != "CK-6100" or ver[:2] != b"\x03\x00":
            raise SystemExit(f"Refusing unexpected device identity: model={model} ver={ver.hex(' ')}")
        if args.target == "1.20" and cur_fw == "1.22" and not args.allow_downgrade:
            raise SystemExit("Refusing 1.22 -> 1.20 downgrade without --allow-downgrade.")
        if args.target is not None and cur_fw == args.target:
            raise SystemExit(f"Device is already on {args.target}; refusing.")
        if idle_s < MIN_SAFE_IDLE_S:
            msg = f"Device idle interval is {idle_s} s (< {MIN_SAFE_IDLE_S} s); raise it first (e.g. ../clicksctl set --idle 300) or pass --allow-low-idle."
            if args.flash and not args.allow_low_idle:
                raise SystemExit(f"Refusing --flash: {msg}")
            print(f"Warning: {msg}", file=sys.stderr)

        if not args.flash:
            print("Dry-run complete (pre-flight checks passed, no A1/A2/A3/A0 packets sent).")
            return 0

        # 1. A1 begin
        rep = sess.transact(pkt_begin(len(image)), CMD_FW_BEGIN)
        if rep.status != 0x00 or len(rep.payload) != 4:
            raise RuntimeError(f"A1 rejected: status=0x{rep.status:02x} payload={rep.payload.hex(' ')}")
        max_sz = struct.unpack(">I", rep.payload)[0]
        if len(image) > max_sz:
            raise RuntimeError(f"Device max size {max_sz} < image size {len(image)}")
        print(f"A1 accepted (device max=0x{max_sz:x})")

        # 2. A2 32-byte chunks
        for offset in range(0, len(image), CHUNK_SIZE):
            chunk = image[offset : offset + CHUNK_SIZE]
            rep = sess.transact(pkt_data(offset, chunk), CMD_FW_DATA)
            if rep.status != 0x00 or len(rep.payload) != 4:
                raise RuntimeError(f"A2 failed at 0x{offset:x}: status=0x{rep.status:02x}")
            next_off = struct.unpack(">I", rep.payload)[0]
            if next_off != offset + len(chunk):
                raise RuntimeError(f"A2 offset mismatch: expected 0x{offset + len(chunk):x}, got 0x{next_off:x}")
            if offset % (CHUNK_SIZE * 64) == 0 or offset + len(chunk) == len(image):
                print(f"A2 {offset + len(chunk)}/{len(image)} bytes")

        # 3. A3 commit
        rep = sess.transact(pkt_commit(len(image)), CMD_FW_COMMIT)
        if rep.status != 0x00 or len(rep.payload) != 4:
            raise RuntimeError(f"A3 commit failed: status=0x{rep.status:02x}")
        committed = struct.unpack(">I", rep.payload)[0]
        print(f"A3 committed ({committed} bytes)")

        # 4. A0 reboot
        if args.no_reboot:
            print("Skipped A0 reboot (--no-reboot).")
        else:
            print("Sending A0 reboot...")
            sess._write(0x03, pkt_reboot())
            time.sleep(0.25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
