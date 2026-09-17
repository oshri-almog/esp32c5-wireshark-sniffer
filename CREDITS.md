# Credits and prior art

Everything in this repository was written for it. No code from the projects below is included, and
nothing here should be read as an endorsement by their authors, who had no part in this tool.
They are named because they came first and the idea grew out of them.

## Prior art

**ESP32 packet sniffer for Wireshark — Abir Mojumder.**
An Arduino sketch for the classic ESP32 that put the radio in promiscuous mode and wrote PCAP bytes
to the serial port. That is where the approach of "let the board speak PCAP and let Wireshark do the
rest" comes from. The firmware here is a fresh ESP-IDF implementation for the ESP32-C5: different
framework, different chip family, different transport (native USB-Serial-JTAG), radiotap headers
instead of plain 802.11, a runtime channel/dwell protocol, and a host handshake.

**SerialShark — [@xdavidhu](https://github.com/xdavidhu).**
A Python script that read an ESP32's serial output and piped it into Wireshark. The idea of feeding
Wireshark from a serial capture comes from there. [`host/sniffer.py`](host/sniffer.py) is an
independent implementation: it speaks this firmware's handshake, frames whole PCAP records and
resynchronises on loss, works on Windows as well as Unix, and manages Wireshark as a child process.

## Standing on

- **Wireshark** and its [extcap interface](https://www.wireshark.org/docs/man-pages/extcap.html),
  which is what lets a board show up as a capture interface with its own settings and toolbar.
- **Espressif's ESP-IDF**, in particular the `esp_wifi` promiscuous-mode API and the
  `examples/network/simple_sniffer` example, which is the reference for how to take frames from the
  Wi-Fi driver safely.
- **radiotap**, for the per-frame radio metadata (channel, signal, noise) that makes the captures
  worth reading.
- **ESP Web Tools** and **esptool-js**, for flashing from a browser.

## Wireshark's "Wireless Toolbar"

Worth being precise, because the names are close. Wireshark has a *Wireless Toolbar* that can retune
a real 802.11 adapter, but it is compiled in only where `libnl`/`nl80211` exist, so it does not
appear on Windows at all, and it can never drive a capture that arrives over a pipe.

The channel controls this tool adds are an **extcap Interface Toolbar**
(*View → Interface Toolbars*), which is a different Wireshark feature and does work on Windows.
