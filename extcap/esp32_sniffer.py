#!/usr/bin/env python3
"""Wireshark extcap plugin for the ESP32 Wi-Fi sniffer.

Every board that is plugged in shows up in Wireshark's interface list, so you start a capture by
double-clicking it. The gear icon next to the interface sets the serial port, the channels to scan and
the time spent on each of them, and the same settings can be changed while capturing from
View -> Interface Toolbars -> ESP32 Wi-Fi sniffer.

Wireshark calls this program like this:
    --extcap-interfaces                       list the boards (and declare the toolbar)
    --extcap-dlts     --extcap-interface ID   the link type the board sends
    --extcap-config   --extcap-interface ID   the settings behind the gear icon
    --capture --fifo PATH --extcap-interface ID [--port COM14] [--channels 1,6,11] [--dwell 250]
"""

import argparse
import os
import re
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "host"))
import sniffer as ss  # noqa: E402  (MarkerScanner, PcapFramer, open_serial, close_serial, ...)

try:
    from serial.tools import list_ports
except ImportError:
    sys.exit("pyserial is missing. Install it with:  pip install pyserial")

ESPRESSIF_USB_JTAG = (0x303A, 0x1001)

# Toolbar controls (numbers are what Wireshark sends back to us)
CTRL_PRESET, CTRL_CHANNELS, CTRL_DWELL, CTRL_APPLY, CTRL_STATUS = 0, 1, 2, 3, 4

# Control pipe commands
CMD_INITIALIZED, CMD_SET, CMD_ADD, CMD_REMOVE = 0, 1, 2, 3
CMD_ENABLE, CMD_DISABLE, CMD_STATUSBAR, CMD_INFO, CMD_WARNING, CMD_ERROR = 4, 5, 6, 7, 8, 9

DEFAULT_CHANNELS = "1,6,11"
DEFAULT_DWELL = 250

# How long a port that has not answered START yet is given before it is reopened. A board answers
# with its marker and PCAP header immediately, so this only has to outlast a reboot, not a quiet
# channel. It is never applied to a synced stream, where silence means nothing is on the air.
STALL_TIMEOUT = 6.0

LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_IEEE802_15_4_TAP = 283

# A board can listen with its Wi-Fi radio or with its 802.15.4 one, but not both: they share the
# antenna path and 802.15.4 loses the arbitration, so running both would quietly drop frames. Each
# board therefore offers one interface per radio, and only one of them can capture at a time.
MODE_WIFI, MODE_154 = "wifi", "802154"
MODES = {
    MODE_WIFI: {
        "suffix": "",
        "label": "Wi-Fi sniffer",
        "linktype": LINKTYPE_IEEE802_11_RADIOTAP,
        "dlt_name": "IEEE802_11_RADIOTAP",
        "dlt_display": "802.11 plus radiotap header",
        "default_channels": "1,6,11",
    },
    MODE_154: {
        "suffix": "-154",
        "label": "Zigbee/Thread sniffer",
        "linktype": LINKTYPE_IEEE802_15_4_TAP,
        "dlt_name": "IEEE802_15_4_TAP",
        "dlt_display": "IEEE 802.15.4 plus TAP pseudo-header",
        "default_channels": "11-26",
    },
}
# The PCAP file header Wireshark expects before any packet. We send it ourselves the moment the capture
# starts, instead of waiting to pass on the one the board sends: Wireshark does not show a single packet
# from ANY interface until every interface in the capture has produced its header, so a board that is
# unplugged or slow to answer would otherwise hold up all the others.
def pcap_global_header(linktype):
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)

CHANNEL_GROUPS_154 = [
    ("g154", "802.15.4 (Zigbee and Thread)", list(range(11, 27))),
]

# Every channel the radio can tune to, grouped the way they are shown in the tick list
CHANNEL_GROUPS = [
    ("g24", "2.4 GHz", list(range(1, 15))),
    ("g5low", "5 GHz low (UNII-1/2A)", list(range(36, 65, 4))),
    ("g5mid", "5 GHz middle (UNII-2C, radar)", list(range(100, 145, 4))),
    ("g5high", "5 GHz high (UNII-3)", list(range(149, 178, 4))),
]
GROUP_IDS = {gid for gid, _, _ in CHANNEL_GROUPS + CHANNEL_GROUPS_154}


def mode_of(interface):
    """Which radio an interface name asks for."""
    return MODE_154 if (interface or "").endswith(MODES[MODE_154]["suffix"]) else MODE_WIFI


def groups_for(mode):
    return CHANNEL_GROUPS_154 if mode == MODE_154 else CHANNEL_GROUPS


def channel_ok_for(mode, channel):
    return ss.channel_is_valid(channel, mode)

# Ready-made channel lists for the toolbar and the settings dialog
PRESETS = [
    ("1,6,11", "2.4 GHz - the three that do not overlap (1, 6, 11)"),
    ("1-13", "2.4 GHz - every channel (1-13)"),
    ("1", "2.4 GHz - channel 1 only"),
    ("6", "2.4 GHz - channel 6 only"),
    ("11", "2.4 GHz - channel 11 only"),
    ("36,40,44,48", "5 GHz - the low band (36-48)"),
    ("149,153,157,161,165", "5 GHz - the high band (149-165)"),
    ("36-165", "5 GHz - every channel"),
    ("1-13,36-165", "Both bands - every channel"),
]

# no { } in this regex: Wireshark's extcap parser splits the reply on braces
CHANNELS_REGEX = r"^ *[0-9]+ *(- *[0-9]+ *)?(, *[0-9]+ *(- *[0-9]+ *)?)* *$"


def out(line):
    sys.stdout.write(line + "\n")


def parse_channel_spec_safe(spec, mode=MODE_WIFI):
    """parse_channel_spec but never raises: used where a bad value should not stop the plugin."""
    try:
        return ss.parse_channel_spec(spec, mode)
    except ValueError:
        return []


def channels_from_ticks(raw, mode=MODE_WIFI):
    """Turn what a tick list hands back into a channel list.

    Wireshark sends the ticked values comma separated. The group headings are ticked values too, so they
    are dropped, and ticking a heading is taken as "all the channels under it".
    """
    channels, groups = [], []
    for token in str(raw).replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if token in GROUP_IDS:
            groups.append(token)
            continue
        try:
            channel = int(token)
        except ValueError:
            continue  # something we do not recognise: better to ignore than to refuse the capture
        if channel_ok_for(mode, channel) and channel not in channels:
            channels.append(channel)

    # A ticked heading may arrive on its own, or next to the channels under it. Only fall back to
    # "the whole band" when no individual channel came with it, so ticking three channels in a band
    # never turns into the whole band.
    if not channels:
        for gid in groups:
            for group_id, _, members in groups_for(mode):
                if group_id == gid:
                    channels.extend(m for m in members if m not in channels)
    return channels


# ----------------------------------------------------------------------------------------------
# Finding the boards
# ----------------------------------------------------------------------------------------------

def find_boards():
    """Every ESP32 that is plugged in right now, in a stable order."""
    boards = [p for p in list_ports.comports() if (p.vid, p.pid) == ESPRESSIF_USB_JTAG]
    return sorted(boards, key=lambda p: natural_key(p.device))


def natural_key(device):
    m = re.search(r"(\d+)$", device or "")
    return (device[:m.start()] if m else device, int(m.group(1)) if m else 0)


def board_id(port_info, mode=MODE_WIFI):
    """A name for the board that survives it moving to another USB socket.

    Most boards report their MAC address as the USB serial number, which is perfect. The ones that
    report nothing useful fall back to the port name, and then they do move around.
    """
    serial = (port_info.serial_number or "").strip()
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", serial):
        base = "esp32-" + serial.replace(":", "").replace("-", "").lower()
    else:
        base = "esp32-" + (port_info.device or "unknown").lower()
    return base + MODES[mode]["suffix"]


def board_label(port_info, mode=MODE_WIFI):
    serial = (port_info.serial_number or "").strip()
    what = MODES[mode]["label"]
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", serial):
        return "ESP32 %s (%s, %s)" % (what, port_info.device, serial.upper())
    return "ESP32 %s (%s)" % (what, port_info.device)


def port_for_interface(interface, explicit_port):
    """Work out which serial port to talk to. The port chosen in the settings dialog always wins."""
    if explicit_port:
        return explicit_port
    mode = mode_of(interface)
    for p in find_boards():
        if board_id(p, mode) == interface:
            return p.device
    # The board was unplugged, or moved and reports no serial number: fall back to the name it had.
    bare = (interface or "")
    if bare.endswith(MODES[MODE_154]["suffix"]):
        bare = bare[:-len(MODES[MODE_154]["suffix"])]
    m = re.fullmatch(r"esp32-((?:com|tty|cu\.)\S+)", bare, re.IGNORECASE)
    if m:
        return m.group(1).upper() if m.group(1).lower().startswith("com") else m.group(1)
    return None


# ----------------------------------------------------------------------------------------------
# The four things Wireshark asks for
# ----------------------------------------------------------------------------------------------

def extcap_interfaces():
    out("extcap {version=1.0}{display=ESP32 sniffer}"
        "{help=https://github.com/oshri-almog/esp32c5-wireshark-sniffer}")
    # Each board appears once per radio: Wi-Fi and 802.15.4 (Zigbee/Thread). Only one of the two can
    # capture at a time, because they share the antenna.
    for p in find_boards():
        for mode in (MODE_WIFI, MODE_154):
            out("interface {value=%s}{display=%s}" % (board_id(p, mode), board_label(p, mode)))

    # The toolbar under View -> Interface Toolbars
    out("control {number=%d}{type=selector}{display=Channels}"
        "{tooltip=Pick a ready-made channel list and switch to it straight away}" % CTRL_PRESET)
    out("control {number=%d}{type=string}{display=Custom}{validation=%s}"
        "{placeholder=6 or 1,6,11 or 1-11}"
        "{tooltip=One channel (6), several (1,6,11), a range (1-11) or a mix (1-13,36,149-165)}"
        % (CTRL_CHANNELS, CHANNELS_REGEX))
    out("control {number=%d}{type=string}{display=Dwell ms}{validation=^ *[0-9]+ *$}"
        "{tooltip=How long to stay on each channel before hopping to the next one}" % CTRL_DWELL)
    out("control {number=%d}{type=button}{display=Apply}"
        "{tooltip=Send the Custom channels and Dwell time to the board}" % CTRL_APPLY)
    out("control {number=%d}{type=string}{display=Status}{tooltip=What the board is doing}" % CTRL_STATUS)

    for value, display in PRESETS:
        out("value {control=%d}{value=%s}{display=%s}%s"
            % (CTRL_PRESET, value, display, "{default=true}" if value == DEFAULT_CHANNELS else ""))


def extcap_dlts(interface):
    m = MODES[mode_of(interface)]
    out("dlt {number=%d}{name=%s}{display=%s}" % (m["linktype"], m["dlt_name"], m["dlt_display"]))


def extcap_config(interface):
    mode = mode_of(interface)
    boards = find_boards()
    current = port_for_interface(interface, None)

    out("arg {number=0}{call=--port}{display=Serial port}{type=selector}{group=Board}"
        "{tooltip=The board to capture from. The list is refreshed every time this dialog opens.}")
    if not boards:
        out("value {arg=0}{value=}{display=no ESP32 found - plug one in and reopen this dialog}{default=true}")
    for p in boards:
        out("value {arg=0}{value=%s}{display=%s}%s"
            % (p.device, board_label(p, mode), "{default=true}" if p.device == current else ""))

    # Tick list of channels, grouped by band. Ticking a heading takes everything under it.
    default_ticks = set(parse_channel_spec_safe(MODES[mode]["default_channels"], mode))
    # {required=true} matters: without it Wireshark leaves the option out entirely when the ticks happen to
    # match the defaults, and the plugin would never hear what was chosen.
    out("arg {number=1}{call=--channels}{display=Channels to scan}{type=multicheck}{group=Scanning}"
        "{required=true}"
        "{tooltip=Tick the channels to scan. Tick a heading to take all of them.}")
    for gid, gname, members in groups_for(mode):
        out("value {arg=1}{value=%s}{display=%s}{enabled=true}" % (gid, gname))
        for ch in members:
            out("value {arg=1}{value=%d}{display=Channel %d}{enabled=true}{parent=%s}%s"
                % (ch, ch, gid, "{default=true}" if ch in default_ticks else ""))

    out("arg {number=2}{call=--dwell}{display=Dwell time (ms)}{type=integer}{range=20,60000}"
        "{default=%d}{group=Scanning}"
        "{tooltip=Time spent on each channel. Ignored when only one channel is ticked.}"
        % DEFAULT_DWELL)
    if mode == MODE_WIFI:
        out("arg {number=3}{call=--preset}{display=Or a ready-made list}{type=selector}{group=Scanning}"
            "{tooltip=Anything other than Custom overrides the ticks above}")
        out("value {arg=3}{value=}{display=Custom (use the ticks above)}{default=true}")
        for value, display in PRESETS:
            out("value {arg=3}{value=%s}{display=%s}" % (value, display))


# ----------------------------------------------------------------------------------------------
# The toolbar's control pipes
# ----------------------------------------------------------------------------------------------

class ControlPipes:
    """Reads what the user does in the toolbar, and writes back status text."""

    def __init__(self, in_path, out_path, on_change):
        self.on_change = on_change
        self.fh_in = open(in_path, "rb", 0) if in_path else None
        self.fh_out = open(out_path, "wb", 0) if out_path else None
        self.lock = threading.Lock()
        self.pending = {}
        self.running = True

    def send(self, control, command, payload=b""):
        if self.fh_out is None:
            return
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        packet = struct.pack(">sBHBB", b"T", 0, len(payload) + 2, control, command) + payload
        try:
            with self.lock:
                self.fh_out.write(packet)
                self.fh_out.flush()
        except (OSError, ValueError):
            self.running = False

    def status(self, text):
        self.send(CTRL_STATUS, CMD_SET, text)

    def info_bar(self, text):
        self.send(CTRL_STATUS, CMD_STATUSBAR, text)

    def start(self):
        if self.fh_in is None:
            return
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self):
        while self.running:
            try:
                header = self.fh_in.read(6)
                if not header or len(header) < 6:
                    break
                _sync, _pad, length, control, command = struct.unpack(">sBHBB", header)
                payload = self.fh_in.read(length - 2) if length > 2 else b""
            except (OSError, ValueError, struct.error):
                break
            try:
                self._handle(control, command, payload.decode("utf-8", "replace"))
            except Exception as e:  # never let the toolbar kill the capture
                self.status("error: %s" % e)
        self.running = False

    def _handle(self, control, command, value):
        if command == CMD_INITIALIZED:
            self.on_change("initialized", None)
        elif command == CMD_SET:
            if control == CTRL_PRESET:
                self.on_change("channels", value)          # a preset applies straight away
            elif control == CTRL_CHANNELS:
                self.pending["channels"] = value           # typed text waits for Apply
            elif control == CTRL_DWELL:
                self.pending["dwell"] = value
            elif control == CTRL_APPLY:
                for key, val in list(self.pending.items()):
                    self.on_change(key, val)
                self.pending.clear()
        elif command == CMD_ADD and control == CTRL_APPLY:
            # a button press arrives as a "button pressed" event on some builds
            for key, val in list(self.pending.items()):
                self.on_change(key, val)
            self.pending.clear()


# ----------------------------------------------------------------------------------------------
# Capture
# ----------------------------------------------------------------------------------------------

def extcap_capture(interface, fifo_path, port, channels, dwell, mode=MODE_WIFI):
    if not port:
        sys.exit("No ESP32 found for interface %r. Plug the board in, or choose the serial port "
                 "in the interface settings (the gear icon)." % interface)

    control = ControlPipes(getattr(extcap_capture, "control_in", None),
                           getattr(extcap_capture, "control_out", None),
                           on_change=lambda k, v: settings_changed(k, v))
    state = {"serial": None, "channels": channels, "dwell": dwell, "packets": 0, "mode": mode}

    def settings_changed(key, value):
        if key == "initialized":
            control.status(describe())
            return
        ser = state["serial"]
        if ser is None:
            return
        try:
            if key == "channels":
                # Refuse nonsense before the board sees it, in this radio's own numbering
                picked = ss.parse_channel_spec(value, state["mode"])
                bad = [c for c in picked if not channel_ok_for(state["mode"], c)]
                if bad:
                    raise ValueError("channel %d is not valid for this radio" % bad[0])
                ser.write(b"CHANNELS %s\n" % value.encode())
                state["channels"] = value
            elif key == "dwell":
                ms = int(value)
                if not 20 <= ms <= 60000:
                    raise ValueError("dwell must be between 20 and 60000 ms")
                ser.write(b"DWELL %d\n" % ms)
                state["dwell"] = ms
        except ValueError as e:
            control.status("ignored: %s" % e)
            control.info_bar("ESP32 sniffer: %s" % e)
            return
        except (OSError, ValueError):
            return
        control.status(describe())

    def describe():
        return "%s | channels %s | %s ms | %d frames" % (
            port, state["channels"], state["dwell"], state["packets"])

    control.start()

    ser = None
    scanner, framer = ss.MarkerScanner(), ss.PcapFramer()
    # Claiming the link type up front also stops the framer passing the board's own header on, which
    # would be a second header in the middle of the stream.
    framer.linktype = MODES[mode]["linktype"]
    synced, nonce, last_start, last_byte = False, None, 0.0, 0.0
    fifo = open(fifo_path, "wb")
    fifo.write(pcap_global_header(MODES[mode]["linktype"]))
    fifo.flush()
    try:
        while True:
            try:
                if ser is None:
                    ser = ss.open_serial(port, 921600, reset=False)
                    state["serial"] = ser
                    control.status("%s opened" % port)
                    now = time.monotonic()
                    nonce, last_start, last_byte = send_start(ser, state), now, now
                data = ser.read(ser.in_waiting or 1)
                if data:
                    last_byte = time.monotonic()
                elif not synced and time.monotonic() - last_start > 2.0:
                    # Nothing yet: ask again. A write is also how a port whose board has rebooted
                    # gives itself away, which is why send_start() is inside this try.
                    nonce, last_start = send_start(ser, state), time.monotonic()
                if not synced and time.monotonic() - last_byte > STALL_TIMEOUT:
                    # A board that reboots takes its USB device with it, and Windows does not always
                    # fail the reads and writes that follow -- the handle can stay open and silent.
                    # Only before the stream has synced, though: a board answers START with its
                    # marker and header straight away, so silence before that means the port is no
                    # longer the board. Once synced, silence is just a quiet channel and expected.
                    raise OSError("no answer for %.0f s, reopening" % STALL_TIMEOUT)
            except (OSError, ValueError) as e:
                if ser is not None:
                    ss.close_serial(ser)
                    ser = state["serial"] = None
                    synced = False
                    framer.resync()
                    scanner.buf.clear()
                control.status("%s: %s" % (port, e))
                time.sleep(1)
                continue

            if data:
                items, synced = feed(data, scanner, framer, synced, nonce)
                for item in items:
                    fifo.write(item)
                    state["packets"] = framer.records
                fifo.flush()
    except (BrokenPipeError, OSError):
        pass  # Wireshark stopped the capture and closed the pipe
    finally:
        control.running = False
        ss.close_serial(ser)
        try:
            fifo.close()
        except OSError:
            pass


def send_start(ser, state):
    import secrets
    nonce = secrets.token_hex(4).encode()
    # MODE first and on its own: it decides the link type, and the channel numbering differs between
    # the two radios, so the channel list has to follow it rather than precede it.
    #
    # A board already listening with the radio we want answers instantly. One that is not reboots,
    # because the radio is chosen at boot and never handed over while running. Then this port
    # disappears mid-sentence and the rest of these commands go nowhere -- which is fine: the capture
    # loop reconnects when the port comes back, calls this again, and by then the board agrees.
    #
    # Write errors are deliberately not caught here. A board that has just rebooted is most often
    # found by a write failing, and swallowing that left the capture holding a dead port for good.
    # The caller treats it as a disconnect and reopens.
    cmd = b"MODE %s\n" % (b"802154" if state["mode"] == MODE_154 else b"WIFI")
    ser.write(cmd)
    time.sleep(0.3)
    cmd = b"CHANNELS %s\n" % str(state["channels"]).encode()
    cmd += b"DWELL %d\n" % int(state["dwell"])
    cmd += b"START %d %s\n" % (time.time_ns() // 1000, nonce)
    ser.write(cmd)
    return nonce


def feed(data, scanner, framer, synced, nonce):
    """Same two-step as SerialShark: find our start marker, then cut whole pcap records out."""
    items = []
    while True:
        if not synced:
            data = scanner.feed(data, nonce)
            if data is None:
                return items, False
            synced = True
        items += framer.feed(data)
        if not framer.sync_lost:
            return items, True
        synced = False
        data = framer.resync()


# ----------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, add_help=False)
    ap.add_argument("--extcap-interfaces", action="store_true")
    ap.add_argument("--extcap-dlts", action="store_true")
    ap.add_argument("--extcap-config", action="store_true")
    ap.add_argument("--extcap-version", nargs="?", default=None)
    ap.add_argument("--extcap-interface")
    ap.add_argument("--extcap-reload-option")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--fifo")
    ap.add_argument("--extcap-control-in")
    ap.add_argument("--extcap-control-out")
    ap.add_argument("--port")
    ap.add_argument("--channels", default=DEFAULT_CHANNELS)
    ap.add_argument("--preset", default="")
    ap.add_argument("--dwell", type=int, default=DEFAULT_DWELL)
    ap.add_argument("-h", "--help", action="store_true")
    args, _unknown = ap.parse_known_args()

    if args.help:
        ap.print_help()
        return 0
    if args.extcap_interfaces or args.extcap_version is not None:
        extcap_interfaces()
        return 0
    if args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
        return 0
    if args.extcap_config:
        extcap_config(args.extcap_interface)
        return 0
    if args.capture:
        if not args.fifo:
            sys.exit("--capture needs --fifo")
        mode = mode_of(args.extcap_interface)
        if args.channels == DEFAULT_CHANNELS and mode == MODE_154:
            args.channels = MODES[mode]["default_channels"]  # the Wi-Fi default means nothing here
        if args.preset and mode == MODE_WIFI:
            channels = args.preset                      # a ready-made list wins over the ticks
            if not parse_channel_spec_safe(channels, mode):
                sys.exit("Channels: %r is not a channel list" % channels)
        else:
            # The tick list hands back something like "g24,1,6,11"; a typed spec such as "1-11" also works,
            # so both the dialog and the command line are accepted here.
            ticked = (channels_from_ticks(args.channels, mode)
                      or [c for c in parse_channel_spec_safe(args.channels, mode)
                          if channel_ok_for(mode, c)])
            if not ticked:
                sys.exit("No channels selected. Tick at least one in the interface settings (the gear icon).")
            channels = ",".join(str(c) for c in ticked)
        extcap_capture.control_in = args.extcap_control_in
        extcap_capture.control_out = args.extcap_control_out
        extcap_capture(args.extcap_interface, args.fifo,
                       port_for_interface(args.extcap_interface, args.port), channels, args.dwell, mode)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(newline="\n")  # extcap replies are line based, never CRLF
    except Exception:
        pass
    sys.exit(main())
