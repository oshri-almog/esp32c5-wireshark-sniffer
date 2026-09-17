# ESP32-C5 Wireshark Sniffer

**Multiple ESP32-C5 dual-band Wi-Fi sniffer interfaces for Wireshark, with a live channel toolbar.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/host-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Chip](https://img.shields.io/badge/chip-ESP32--C5-red)
![Wireshark](https://img.shields.io/badge/Wireshark-4.2%2B-1679A7)

Turn cheap ESP32-C5 boards into 802.11 sniffers that appear in Wireshark as ordinary capture
interfaces. Plug in three boards and Wireshark lists three interfaces; capture from all of them at
once and the frames merge into one window. Pick the channels from a tick list, and change them while
the capture is running.

Both bands, on the same board: 2.4 GHz channels 1–14 and 5 GHz 36–177.

### ➜ [Flash a board from your browser](https://oshri-almog.github.io/esp32c5-wireshark-sniffer/)

No toolchain needed — Chrome or Edge talks to the board directly.

---

## Why this exists

A USB Wi-Fi adapter in monitor mode watches one channel at a time and, on Windows, cannot be retuned
from inside Wireshark at all: the *Wireless Toolbar* that would do it is compiled in only where
Linux's `nl80211` exists. An ESP32-C5 costs a few dollars, does both bands, and can be told to retune
over its own USB link — so the channel controls can live in Wireshark after all, as an
[extcap interface toolbar](CREDITS.md#wiresharks-wireless-toolbar).

## What it does

| | |
|---|---|
| **One interface per board** | Boards are discovered by USB ID and identified by MAC, so it does not matter which COM number Windows hands out this time. |
| **Several boards at once** | Tick two or three in Wireshark's interface list; frames merge into one capture, tagged per board. Point them at different bands to cover more spectrum than one radio can. |
| **Channels, any shape** | `6` · `1,6,11` · `1-11` · `1-13,36,149-165`. Tick them in a list in the interface options, or type them. |
| **Live retuning** | *View → Interface Toolbars* gives a channel picker and dwell time that take effect mid-capture. |
| **All frame types** | Management, control and data — including ACK, RTS/CTS and Block Ack. |
| **Radio metadata** | A radiotap header per frame: channel, frequency, signal and noise in dBm. |

## Quick start

```bash
git clone https://github.com/oshri-almog/esp32c5-wireshark-sniffer
cd esp32c5-wireshark-sniffer
pip install -r requirements.txt
python extcap/install.py
```

Then flash a board — [from the browser](https://oshri-almog.github.io/esp32c5-wireshark-sniffer/),
or with ESP-IDF:

```bash
cd firmware
idf.py set-target esp32c5
idf.py -p COM14 flash
```

Open Wireshark, press <kbd>F5</kbd>, and double-click the board.

**Full step-by-step guide, with screenshots and troubleshooting:
[the documentation site](https://oshri-almog.github.io/esp32c5-wireshark-sniffer/).**

## What is in here

```
firmware/     ESP-IDF project for the ESP32-C5 (the sniffer itself)
extcap/       the Wireshark plugin, and install.py which registers it
host/         sniffer.py, for captures from the command line
wireshark/    the WLAN-detail Wireshark profile (columns, colours, filter buttons)
docs/         the documentation site and the browser flasher
tests/        offline tests for the PCAP framing and the toolbar protocol
```

## Command line

Most people let Wireshark drive. For scripted captures:

```bash
python host/sniffer.py -p COM14                          # open Wireshark on one board
python host/sniffer.py -p COM14 -c 1,6,11 -d 200         # channels and dwell time
python host/sniffer.py -p COM14 --no-wireshark --duration 60 -f out.pcap
```

## Firmware protocol

The board speaks plain lines over its USB port, so you can drive it from anything:

| Command | |
|---|---|
| `START [<unix µs>\|0] [<nonce>]` | Begin a stream: marker line, then the PCAP global header. |
| `CHANNELS <spec>` | Channels to scan (`6`, `1,6,11`, `1-11`, …). `0` or `AUTO` restores the built-in list. |
| `DWELL <ms>` | Time on each channel, 20–60000 ms. |

Build-time defaults (bands, starting channel, control frames, buffer sizes) are in
`idf.py menuconfig` → *Packet Sniffer Configuration*.

## Requirements

- An **ESP32-C5** board, connected by its **native USB** port (USB VID `303A`, PID `1001`)
- **Wireshark** 4.2+
- **Python** 3.8+ with `pyserial`
- **ESP-IDF** v5.5+ only if you want to build the firmware yourself

## Known limitations

- **One channel at a time per board.** The radio is single-tuner; hopping trades coverage for
  completeness. Use several boards to watch several channels at once.
- **A few malformed frames per thousand.** The Wi-Fi driver reports some MIMO frames with metadata
  that does not match the payload. Harmless, and clearly flagged by Wireshark.
- **Throughput.** USB-Serial-JTAG manages a few hundred kB/s. On a busy channel the firmware drops
  whole frames rather than blocking, so the stream stays valid.
- **Drop counters go to UART only**, to keep the USB stream free of anything but capture data.

## Licence and credits

MIT — see [LICENSE](LICENSE). Prior art that inspired this is acknowledged in
[CREDITS.md](CREDITS.md); no third-party code is included.

Only capture traffic on networks you own or are authorised to test.
