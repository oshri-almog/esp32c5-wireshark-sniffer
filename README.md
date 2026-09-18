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
| **Zigbee and Thread** | The same board also sniffs IEEE 802.15.4, channels 11–26, as a second interface per board. Wireshark dissects Zigbee and Thread from it without any extra plugin. |

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
wireshark/    the ESP32-Sniffer Wireshark profile (columns, colours, filter buttons)
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
| `MODE WIFI\|802154` | Which radio to listen with. Remembered in flash; changing it reboots the board. |
| `TXTEST [n]` | **Transmits** `n` 802.15.4 test frames (802.15.4 mode only), so a second board can prove the receive path without any Zigbee hardware around. Nothing else ever transmits. |

Build-time defaults (bands, starting channel, control frames, buffer sizes) are in
`idf.py menuconfig` → *Packet Sniffer Configuration*.

## Zigbee and Thread

Every board offers a second interface, *ESP32 Zigbee/Thread sniffer*, that captures raw IEEE 802.15.4
on channels 11–26 and hands Wireshark an
[802.15.4 TAP](https://www.wireshark.org/docs/dfref/w/wpan-tap.html) header with channel, RSSI, LQI
and a timestamp. Wireshark dissects Zigbee, 6LoWPAN and Thread from that on its own — nothing else to
install. Pick the interface and it works like the Wi-Fi one, tick list and toolbar included.

Zigbee traffic above the network layer is encrypted; to read it, put the network key into
*Preferences → Protocols → ZigBee NWK*. Thread is dissected as 6LoWPAN and IPv6 without a key.

One radio, one protocol: a board captures Wi-Fi **or** 802.15.4, never both at once. Choosing the
other interface reboots the board, which takes a couple of seconds and is why the radio is picked at
boot rather than swapped live — handing the antenna over at runtime leaves the PHY in a state that
only unplugging the board clears.

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
- **A board remembers its radio across reboots.** One last used for Zigbee or Thread comes back in
  that mode, sends its `<<START>>` marker and header, and then sits quietly on an empty band — which
  reads as a hang. Wireshark always sets the radio itself; from the command line pass `--mode wifi`.
- **A board that has run 802.15.4 can come back deaf to Wi-Fi.** Rare, and no reset clears it —
  unplug the board. The firmware shuts the radio down cleanly before rebooting into the other mode,
  which is what keeps this from happening in normal use.

## Licence and credits

MIT — see [LICENSE](LICENSE). Prior art that inspired this is acknowledged in
[CREDITS.md](CREDITS.md); no third-party code is included.

Only capture traffic on networks you own or are authorised to test.
