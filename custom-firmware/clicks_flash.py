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
CompanionReply = _clicksctl.CompanionReply
encode_getter = _clicksctl.encode_getter
usb = _clicksctl.usb

RECOVERY_VID = 0x352E
RECOVERY_PID = 0x2307
RECOVERY_EP_IN = 0x81
RECOVERY_EP_OUT = 0x01
RECOVERY_PKT_SIZE = 64

HERE = Path(__file__).resolve().parent

CK6100_IMAGES = {
    "1.23-Custom": (
        HERE / "iKeyboard_CK-6100_V123_300_Custom.bin",
        "435623f49c9f793c253c7efa94c7f791530ed9033053f097dfb7323a91ec06e6",
    ),
    "1.23-Custom-PT": (
        HERE / "iKeyboard_CK-6100_V123_300_Custom_PT.bin",
        "454cec0e772be84b8f863f28002446c15b6e104258357a7b9c7c173d537eb8ac",
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


class RecoverySession:
    """Plain 64-byte Vendor HID session for CK-6100 bootloader recovery (352e:2307)."""

    def __init__(self, serial: str | None = None, *, timeout_ms: int = 2000):
        self.serial = serial
        self.timeout_ms = timeout_ms
        self.dev = None
        self.actual_serial = ""
        self._detached = False

    def __enter__(self) -> "RecoverySession":
        devs = list(usb.core.find(find_all=True, idVendor=RECOVERY_VID, idProduct=RECOVERY_PID))
        if not devs:
            raise RuntimeError(f"No CK-6100 bootloader recovery device ({RECOVERY_VID:04x}:{RECOVERY_PID:04x}) found")
        if self.serial is not None:
            matched = [d for d in devs if (usb.util.get_string(d, d.iSerialNumber) or "") == self.serial]
            if not matched:
                raise RuntimeError(f"No recovery device with serial {self.serial!r}")
            self.dev = matched[0]
        elif len(devs) > 1:
            raise RuntimeError("Multiple recovery devices found; pass --serial")
        else:
            self.dev = devs[0]
        self.actual_serial = usb.util.get_string(self.dev, self.dev.iSerialNumber) or ""
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
                self._detached = True
        except (NotImplementedError, usb.core.USBError):
            pass
        usb.util.claim_interface(self.dev, 0)
        return self

    def _write(self, ep: int, frame: bytes) -> None:
        assert self.dev is not None
        if len(frame) > RECOVERY_PKT_SIZE:
            raise ValueError(f"frame too large ({len(frame)} > {RECOVERY_PKT_SIZE})")
        self.dev.write(ep, frame.ljust(RECOVERY_PKT_SIZE, b"\x00"), timeout=self.timeout_ms)

    def transact(self, frame: bytes, expected_cmd: int):
        assert self.dev is not None
        self._write(RECOVERY_EP_OUT, frame)
        resp = bytes(self.dev.read(RECOVERY_EP_IN, RECOVERY_PKT_SIZE, timeout=self.timeout_ms))
        return CompanionReply.decode(resp, expected_cmd)

    def __exit__(self, *exc) -> None:
        if self.dev is not None:
            try:
                usb.util.release_interface(self.dev, 0)
            except Exception:
                pass
            if self._detached:
                try:
                    self.dev.attach_kernel_driver(0)
                except Exception:
                    pass


def flash_image(sess, image: bytes, *, reboot_ep: int, no_reboot: bool) -> None:
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
    if no_reboot:
        print("Skipped A0 reboot (--no-reboot).")
    else:
        print("Sending A0 reboot...")
        sess._write(reboot_ep, pkt_reboot())
        time.sleep(0.25)


def main() -> int:
    ap = argparse.ArgumentParser(description="CK-6100 firmware flasher (dry-run by default)")
    ap.add_argument("--serial", default=None, help="Target USB serial (required if multiple devices are attached)")
    ap.add_argument("--target", choices=sorted(CK6100_IMAGES), help="Known firmware target (verifies SHA-256)")
    ap.add_argument("--image", type=Path, help="Path to firmware .bin")
    ap.add_argument("--recovery", action="store_true", help="Flash via 352e:2307 bootloader HID recovery mode (no iAP2)")
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

    if args.recovery:
        with RecoverySession(args.serial, timeout_ms=2000) as sess:
            ver = sess.transact(encode_getter(CMD_GET_VERSION), CMD_GET_VERSION).payload
            print(f"Recovery device: serial={sess.actual_serial} raw_ver={ver.hex(' ')}")
            if not args.flash:
                print("Dry-run complete (recovery pre-flight passed, no A1/A2/A3/A0 packets sent).")
                return 0
            flash_image(sess, image, reboot_ep=RECOVERY_EP_OUT, no_reboot=args.no_reboot)
        return 0

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

        flash_image(sess, image, reboot_ep=0x03, no_reboot=args.no_reboot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
