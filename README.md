# Note from an actual human: This is vibecoded AI slop that worked for me so I thought it'd be fun to opensource but please don't take it too seriously and use it with care.

# clicksctl

Standalone, single-file Linux CLI for reading and configuring **Clicks Keyboard** iPhone case settings over USB-C (no iPhone or official app required).

It speaks Apple's iAP2 External Accessory handshake (`com.clickscompanion.protocol`) directly over USB bulk endpoints, then sends the companion settings protocol. It only implements settings reads/writes and **never** sends firmware-update or reboot commands (`A0`–`A3`).

---

## Requirements

- **Linux** with `libusb-1.0`
- **Python 3.10+**
- **`pyusb`** (`pip install pyusb`)

### Non-root USB access (udev rule)

Create `/etc/udev/rules.d/99-clicks.rules`:

```sh
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="352e", ATTR{idProduct}=="2306", MODE="0660", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/99-clicks.rules
sudo udevadm control --reload && sudo udevadm trigger
```

*(Make sure your user is in `plugdev`, or use `TAG+="uaccess"` on a desktop session, then replug the case.)*

---

## Usage

```sh
# List connected Clicks keyboards (shows bus, addr, serial, firmware version)
./clicksctl list

# Read all settings (use --serial if multiple cases are attached)
./clicksctl get
./clicksctl get --serial 4102104619 --json
./clicksctl get --serial 4102104619 --backup backup.json

# Preview changes without writing to flash
./clicksctl set --brightness 64 --timeout 8000 --flag soft_return=on --dry-run

# Apply persistent settings (unchanged values are skipped to avoid unnecessary flash writes)
./clicksctl set --brightness 64 --idle 600
./clicksctl set --flag accs_stop=on --flag tab_to_ctrl=on

# Temporary RAM-only brightness change (resets when unplugged, no flash write)
./clicksctl set --temp-brightness 32

# Restore from a JSON backup
./clicksctl restore backup.json
```

> **Tip:** Persistent changes are written to a 256-byte flash page on the next main-loop pass *after* the USB reply is sent. Wait ~200 ms after `clicksctl set` before unplugging.

---

## Available Settings

| Flag / Option | Range / Values | Notes |
|---|---|---|
| `--brightness` | `0..255` | Persistent backlight PWM brightness |
| `--temp-brightness` | `0..255` | Temporary RAM-only brightness (resets on unplug) |
| `--timeout` | `1000..65535` ms | Backlight auto-off delay after last keypress |
| `--idle` | `>= timeout/1000 .. 65535` s | Inactivity timeout before accessory sleep (`accs_stop`) |
| `--currency` | `dollar`, `cent`, `pound`, `euro`, `rmb` (or `0..4`) | Currency key symbol |
| `--layout` | `us`, `br` (or `0x21`, `0x20`) | Regional layout (`0x21` / `0x20`) |
| `--flag NAME=on\|off` | See behavior flags below | Masked bit update (`0x83`) |

### Behavior Flags (`--flag`)

- `alt_sticky` — Tap-to-latch / double-tap-lock for the `123` number/symbol layer
- `shift_sticky` — Tap-to-latch / double-tap-lock for `Shift`
- `led` — Master backlight LED enable
- `soft_return` — Soft Return mode
- `accs_stop` — Enable accessory sleep (shuts off USB after `--idle` seconds; wakes on keypress)
- `led_switch` — Enable on-keyboard backlight toggle shortcut (`123` + Globe)
- `tab_to_ctrl` — Remap `Tab` to `Ctrl`
- `cursor_mode` — Built-in cursor/arrow-key navigation mode

---

## Compatibility

### Tested & Confirmed
- **`CK-6100`** (iPhone 16 Pro) — verified on both firmware **`1.2.0`** and **`1.2.2`** (`352e:2306`)

### Expected to Work (Untested)
- **`CK-5200`** (iPhone 15 Pro Max) — static disassembly confirms the exact same USB layout, iAP2 session flow, and settings dispatcher (`1.2.2`).
- Other USB-C iPhone **`CK-5xxx` / `CK-6xxx`** models (`CK-5100`, `CK-5110`, `CK-5120`, `CK-5200B`, `CK-5210`, `CK-5220`, `CK-6000`, `CK-6200`, `CK-6400`), assuming they expose USB `352e:2306` with the same iAP2 + `com.clickscompanion.protocol` interface.

### Not Expected to Work
- **Android cases** (Pixel / Razr `CA-*` models) — use raw vendor USB bulk frames directly without the iAP2 handshake.
- **Clicks Power Keyboard** (`CP-1000`, etc.) and Bluetooth models — use Bluetooth HID rather than USB-C iAP2.
- **Lightning iPhone 14 cases** (`CK-4100`, `CK-4200`) — different physical interface; untested.
