#!/usr/bin/env python3
"""Stream a live capture from an ESP32-C5 Wi-Fi sniffer board into Wireshark.

This is the command-line way in. Most people will instead let Wireshark start the capture itself,
through the extcap plugin in ../extcap - see the documentation. This script is handy for scripted
captures, for writing a .pcap without opening a GUI, and for seeing what the board is doing.

    python host/sniffer.py -p COM14                 open Wireshark on one board
    python host/sniffer.py -p COM14 -c 1,6,11       pick the channels to scan
    python host/sniffer.py -p COM14 --no-wireshark --duration 60 -f out.pcap

How it works: the board sends a marker line, then a PCAP global header, then one PCAP record per
frame. This script finds the marker, forwards whole records only, and resynchronises on the next
marker if the stream is ever damaged (board reset, USB hiccup). Run with no arguments and it asks
for the port, baudrate and file name.

The idea of piping an ESP32 serial capture into Wireshark comes from SerialShark by @xdavidhu
(github.com/xdavidhu). This is an independent implementation for the firmware in this repository;
no code from that project is included. See CREDITS.md.
"""

import argparse
import os
import queue
import re
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time

import serial
from serial.tools import list_ports

MARKER_RE = re.compile(rb"<<START>>(?: ([0-9A-Za-z]{1,16}))?\r?\n")
MARKER_TAIL = len(b"<<START>> " + b"x" * 16 + b"\r\n") - 1  # kept between reads, a marker may be split

PCAP_MAGIC = 0xA1B2C3D4
PCAP_GLOBAL_HDR_LEN = 24
PCAP_REC_HDR_LEN = 16
MAX_RECORD_LEN = 16384  # sanity bound used to detect a damaged stream

# start marker immediately followed by a PCAP global header (magic number, version 2.4)
STREAM_START_RE = re.compile(MARKER_RE.pattern + re.escape(struct.pack("<IHH", PCAP_MAGIC, 2, 4)))
STREAM_START_TAIL = MARKER_TAIL + 8

ESPRESSIF_USB_JTAG = (0x303A, 0x1001)
START_RETRY_S = 2.0
WIRESHARK_STARTUP_S = 60.0
WIRESHARK_STALL_S = 10.0

DEFAULT_PROFILE = "ESP32-Sniffer"
# The profile that ships with this project: Wi-Fi columns (channel, rate, signal, SSID, BSSID),
# colouring rules and the Wi-Fi filter buttons. Copied from wireshark/profiles/ on first use.
PROFILE_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "wireshark", "profiles")


# ----------------------------------------------------------------------------------------------
# Channel lists
# ----------------------------------------------------------------------------------------------

MODE_WIFI, MODE_154 = "wifi", "802154"


def channel_is_valid(ch, mode=MODE_WIFI):
    """The channels an ESP32 radio can tune to (same rule as the firmware).

    The two radios number their channels differently and the ranges overlap, so 11 to 14 mean one
    thing on Wi-Fi and another on 802.15.4. Which radio is meant has to be said, not guessed.
    """
    if mode == MODE_154:
        return 11 <= ch <= 26
    return (1 <= ch <= 14
            or (36 <= ch <= 64 and (ch - 36) % 4 == 0)
            or (100 <= ch <= 144 and (ch - 100) % 4 == 0)
            or (149 <= ch <= 177 and (ch - 149) % 4 == 0))


def parse_channel_spec(spec, mode=MODE_WIFI):
    """Turn "6", "1,6,11", "1-11" or "1-13,36,149-165" into an ordered list of channels.

    A single number has to be a real channel; a range keeps the real channels inside it, so "36-64"
    gives 36, 40 ... 64. Duplicates are dropped so no channel gets two turns in a lap.
    """
    what = "802.15.4" if mode == MODE_154 else "Wi-Fi"
    allowed = "11-26" if mode == MODE_154 else "1-14, or 36-177 in steps of 4"
    channels = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty entry in channel list %r" % spec)
        if "-" in part:
            low, _, high = part.partition("-")
            try:
                low, high = int(low), int(high)
            except ValueError:
                raise ValueError("%r is not a channel range like 1-11" % part)
            if high < low:
                raise ValueError("the range %r runs backwards" % part)
            picked = [c for c in range(low, high + 1) if channel_is_valid(c, mode)]
            if not picked:
                raise ValueError("no %s channels in the range %r" % (what, part))
        else:
            try:
                channel = int(part)
            except ValueError:
                raise ValueError("%r is not a channel number" % part)
            if not channel_is_valid(channel, mode):
                raise ValueError("%d is not a %s channel (%s)" % (channel, what, allowed))
            picked = [channel]
        for c in picked:
            if c not in channels:
                channels.append(c)
    if not channels:
        raise ValueError("empty channel list")
    return channels


# ----------------------------------------------------------------------------------------------
# Wireshark
# ----------------------------------------------------------------------------------------------

def find_wireshark(explicit=None):
    candidates = [explicit, os.environ.get("WIRESHARK_EXE"), shutil.which("Wireshark"), shutil.which("wireshark")]
    if sys.platform == "win32":
        import winreg
        subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe"
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    candidates.append(winreg.QueryValueEx(key, "")[0])
            except OSError:
                pass
        for var in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(var):
                candidates.append(os.path.join(os.environ[var], "Wireshark", "Wireshark.exe"))
    elif sys.platform == "darwin":
        candidates.append("/Applications/Wireshark.app/Contents/MacOS/Wireshark")
    for path in candidates:
        if path and os.path.isfile(path.strip('"')):
            return path.strip('"')
    return None


def ensure_profile(name):
    """Install the Wi-Fi profile that ships with this project, unless one of that name already exists."""
    if sys.platform == "win32":
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Wireshark")
    else:
        base = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "wireshark")
    path = os.path.join(base, "profiles", name)
    source = os.path.join(PROFILE_SRC, name)
    try:
        if os.path.isdir(path):
            return name  # yours already, leave it exactly as it is
        if not os.path.isdir(source):
            print("[!] Profile '%s' is not in this repository, using your current profile." % name)
            return None
        os.makedirs(path)
        for entry in sorted(os.listdir(source)):
            src = os.path.join(source, entry)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(path, entry))
        print("[+] Installed Wireshark profile '%s' (%s)" % (name, path))
        return name
    except OSError as e:
        print("[!] Could not install the Wireshark profile (%s), using your current profile." % e)
        return None


def launch_wireshark(exe, title, profile, style=None):
    # -k start capturing now, -i - read the capture from stdin, -l scroll with the live capture
    cmd = [exe, "-k", "-i", "-", "-l", "-o", "gui.window_title:" + title]
    if profile:
        cmd += ["-C", profile]

    env = None
    if style:
        # Qt's native Windows style draws tick boxes with the system theme, and in dark mode an unticked
        # box has no visible outline. The Fusion style draws them itself and is legible in both themes.
        #
        # This has to go through the environment, NOT a "-style" argument: Wireshark parses the command
        # line itself and reads "-style" as its own "-s" (snapshot length) followed by "tyle", then exits
        # with 'The specified snapshot length "tyle" isn't a decimal number'.
        env = dict(os.environ, QT_STYLE_OVERRIDE=style)
    # own process group: Ctrl+C in this console must stop the script, not kill Wireshark
    if sys.platform == "win32":
        extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        extra = {"start_new_session": True}
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, env=env, **extra)


class PipeSink(threading.Thread):
    """Feeds Wireshark from its own thread, so a stalled or closed GUI can never block the serial port."""

    def __init__(self, proc):
        super().__init__(daemon=True)
        self.proc = proc
        self.q = queue.Queue(maxsize=20000)
        self.alive = True
        self.dropped = 0
        self.started = time.monotonic()
        self.write_started = None

    def put(self, item):
        try:
            self.q.put_nowait(item)
        except queue.Full:  # whole records are dropped, the stream stays valid
            self.dropped += 1

    def stalled(self):
        """True when Wireshark has not taken any data for a while, e.g. after "Stop capture"."""
        now = time.monotonic()
        blocked_since = self.write_started
        if blocked_since is None or now - self.started < WIRESHARK_STARTUP_S:  # the GUI takes a while to load
            return False
        return now - blocked_since > WIRESHARK_STALL_S

    def run(self):
        try:
            while True:
                item = self.q.get()
                if item is None:
                    break
                self.write_started = time.monotonic()
                self.proc.stdin.write(item)
                if self.q.empty():
                    self.proc.stdin.flush()
                self.write_started = None
        except (OSError, ValueError):  # Wireshark is gone (Windows reports EINVAL instead of EPIPE)
            pass
        finally:
            self.alive = False
            try:
                self.proc.stdin.close()
            except (OSError, ValueError):
                pass


# ----------------------------------------------------------------------------------------------
# Stream parsing
# ----------------------------------------------------------------------------------------------

class MarkerScanner:
    """Finds the start marker in a byte stream that may contain boot messages or stale capture data."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data, nonce):
        """Returns the bytes following the marker line, or None. With a nonce only that marker is accepted."""
        self.buf += data
        pos = 0
        while True:
            m = MARKER_RE.search(self.buf, pos)
            if m is None:
                break
            if nonce is None or m.group(1) == nonce:
                rest = bytes(self.buf[m.end():])
                self.buf.clear()
                return rest
            pos = m.end()
        del self.buf[:max(pos, len(self.buf) - MARKER_TAIL)]
        return None


class PcapFramer:
    """Cuts the stream into the global header and whole records and notices when it stops making sense."""

    def __init__(self):
        self.buf = bytearray()
        self.linktype = None
        self.records = 0
        self.need_global_hdr = True
        self.scan_pos = 0
        self.sync_lost = None  # reason, set by feed()

    def resync(self):
        """Sync was lost: the next marker is followed by a new global header. Returns the unparsed bytes."""
        rest = bytes(self.buf)
        self.buf.clear()
        self.need_global_hdr = True
        self.scan_pos = 0
        self.sync_lost = None
        return rest

    def feed(self, data):
        """Returns the complete items. Check sync_lost afterwards, then call resync()."""
        self.buf += data
        out = []
        # A start marker in the middle of the records means the board restarted the stream (reset, or a second
        # START). Without this check it would be taken for the payload of a half received record.
        restart = STREAM_START_RE.search(self.buf, self.scan_pos)
        limit = restart.start() if restart else len(self.buf)
        pos = 0
        if self.need_global_hdr and limit >= PCAP_GLOBAL_HDR_LEN:
            magic, major, minor, _, _, _, network = struct.unpack_from("<IHHIIII", self.buf)
            if magic != PCAP_MAGIC or (major, minor) != (2, 4):
                self.sync_lost = "bad PCAP global header"
                return out
            if self.linktype is None:  # Wireshark must get exactly one global header
                self.linktype = network
                out.append(bytes(self.buf[:PCAP_GLOBAL_HDR_LEN]))
            elif network != self.linktype:
                sys.exit("[!] The board now sends link type %d instead of %d, restart the script."
                         % (network, self.linktype))
            pos = PCAP_GLOBAL_HDR_LEN
            self.need_global_hdr = False
        while not self.need_global_hdr and limit - pos >= PCAP_REC_HDR_LEN:
            _, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", self.buf, pos)
            if ts_usec >= 1000000 or incl_len > orig_len or not 0 < incl_len <= MAX_RECORD_LEN:
                self.sync_lost = "damaged PCAP record"
                break
            end = pos + PCAP_REC_HDR_LEN + incl_len
            if end > limit:
                break
            out.append(bytes(self.buf[pos:end]))
            pos = end
            self.records += 1
        if restart and not self.sync_lost:
            self.sync_lost = "the board restarted the stream"
            pos = restart.start()  # what is left in front of the marker is a truncated record
        del self.buf[:pos]
        self.scan_pos = max(0, len(self.buf) - STREAM_START_TAIL)
        return out


# ----------------------------------------------------------------------------------------------
# Serial port
# ----------------------------------------------------------------------------------------------

def set_rts(ser, state):
    ser.rts = state
    ser.dtr = ser.dtr  # the Windows usbser.sys driver only forwards RTS when DTR is written too


def open_serial(port, baud, reset):
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud  # ignored by the USB-Serial-JTAG port, used by UART bridges
    ser.timeout = 0.1
    ser.write_timeout = 1
    # pyserial asserts DTR and RTS when it opens a port. On Espressif boards those two lines drive reset and
    # boot mode, so the defaults can reboot the chip or leave it in the ROM download mode.
    if sys.platform == "win32":
        # Windows applies both at once, in the DCB, before the port comes up
        ser.dtr = False
        ser.rts = False
        ser.open()
    else:
        # POSIX raises both lines when the device node is opened and pyserial then writes DTR before RTS,
        # so clearing them beforehand would pass through "DTR released, RTS asserted", which resets the chip.
        ser.open()
        ser.rts = False
        ser.dtr = False
    if sys.platform == "win32":
        ser.set_buffer_size(rx_size=1 << 20)
    if reset:  # same sequence as esptool's hard reset: pulse RTS (reset) while DTR (boot mode) stays released
        set_rts(ser, True)
        time.sleep(0.2)
        set_rts(ser, False)
        time.sleep(0.2)
    return ser


def close_serial(ser):
    """Close the port and release the OS handle even if close() fails.

    pyserial does several things before it releases the handle, and one of them can fail when the board
    was unplugged or reset in the middle of a transfer. The handle then stays open for as long as this
    program runs, and every attempt to reopen the port is refused with "access denied".
    """
    if ser is None:
        return
    try:
        ser.close()
        return
    except Exception:
        pass
    try:
        if getattr(ser, "_port_handle", None) is not None:  # Windows
            import serial.win32
            serial.win32.CloseHandle(ser._port_handle)
            ser._port_handle = None
        elif getattr(ser, "fd", None) is not None:  # Linux, macOS
            os.close(ser.fd)
            ser.fd = None
    except Exception:
        pass
    ser.is_open = False


def default_port():
    espressif = [p.device for p in list_ports.comports() if (p.vid, p.pid) == ESPRESSIF_USB_JTAG]
    if len(espressif) == 1:
        return espressif[0]
    return "COM3" if sys.platform == "win32" else "/dev/ttyUSB0"


def ask(question, default):
    try:
        answer = input("[?] %s (default '%s'): " % (question, default)).strip()
    except (KeyboardInterrupt, EOFError):
        sys.exit("\n[+] Exiting...")
    return answer or str(default)


def parse_args():
    ap = argparse.ArgumentParser(description="Stream the ESP32 packet sniffer capture into Wireshark.")
    ap.add_argument("-p", "--port", help="serial port, e.g. COM14 or /dev/ttyACM0")
    ap.add_argument("-b", "--baud", type=int, help="baudrate (default 921600, ignored by native USB ports)")
    ap.add_argument("-f", "--file", help="capture file to write (default capture.pcap)")
    ap.add_argument("-c", "--channels", metavar="SPEC",
                    help="channels to scan: one (6), several (1,6,11), a range (1-11) or a mix "
                         "(1-13,36,149-165). Default: whatever the firmware was built with.")
    ap.add_argument("-d", "--dwell", type=int, metavar="MS",
                    help="time spent on each channel before hopping to the next one, in ms")
    ap.add_argument("-m", "--mode", choices=["wifi", "802154"],
                    help="radio to capture with: wifi, or 802154 for Zigbee and Thread. The board "
                         "reboots if this is not the one it is already using. Default: leave it alone.")
    ap.add_argument("--reset", action="store_true", help="reset the board (RTS pulse) after opening the port")
    ap.add_argument("--no-handshake", action="store_true",
                    help="only wait for the <<START>> line printed at boot (original Arduino firmware)")
    ap.add_argument("--wireshark", help="path of the Wireshark executable")
    ap.add_argument("--no-wireshark", action="store_true", help="only write the capture file")
    ap.add_argument("--profile", default=DEFAULT_PROFILE,
                    help="Wireshark profile to use, created if missing (default %(default)s)")
    ap.add_argument("--no-profile", action="store_true", help="use your current Wireshark profile")
    ap.add_argument("--style", default="Fusion",
                    help="Qt widget style for Wireshark. The default keeps tick boxes visible in dark "
                         "mode; pass --style '' to leave Wireshark's own styling alone.")
    ap.add_argument("--duration", type=float, help="stop after this many seconds of capture")
    args = ap.parse_args()
    if args.channels is not None:
        try:
            channels = parse_channel_spec(args.channels, args.mode or MODE_WIFI)
        except ValueError as e:
            ap.error("--channels: %s" % e)
        print("[i] Scanning %d channel(s): %s"
              % (len(channels), ",".join(str(c) for c in channels)))
    if args.dwell is not None and not 20 <= args.dwell <= 60000:
        ap.error("--dwell must be between 20 and 60000 ms")
    if args.no_handshake and (args.channels is not None or args.dwell is not None):
        ap.error("--channels and --dwell need the START handshake, so they cannot be used with --no-handshake")

    interactive = args.port is None  # no port given: ask like the original script did
    if interactive:
        print("[i] Serial ports: " + (", ".join("%s (%s)" % (p.device, p.description)
                                                 for p in list_ports.comports()) or "none found"))
        args.port = ask("Select a serial port", default_port())
    while args.baud is None:
        try:
            args.baud = int(ask("Select a baudrate", 921600)) if interactive else 921600
        except ValueError:
            print("[!] Please enter a number!")
    if args.file is None:
        args.file = ask("Select a filename", "capture.pcap") if interactive else "capture.pcap"
    return args


# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------

def main():
    args = parse_args()

    wireshark = None
    if not args.no_wireshark:
        wireshark = find_wireshark(args.wireshark)
        if wireshark is None:
            sys.exit("[!] Wireshark not found. Use --wireshark PATH, or --no-wireshark to only write the file.")
    profile = None if (args.no_profile or not wireshark) else ensure_profile(args.profile)

    scanner = MarkerScanner()
    framer = PcapFramer()
    ser = proc = sink = None
    synced = False
    nonce = None
    last_start = 0.0
    start_attempts = 0
    reset_pending = args.reset
    open_failures = 0
    bytes_in = 0
    sync_time = last_status = None
    stuck = False

    def send_start():
        nonlocal nonce, last_start, start_attempts
        nonce = secrets.token_hex(4).encode()  # tells the answer to this START from older markers
        # The radio, if one was asked for. Sent on its own and first: the board reboots when this is
        # not the radio it booted with, and the channel numbering differs between the two. Without
        # --mode the board is left on whatever radio it is already using.
        if args.mode:
            try:
                ser.write(b"MODE %s\n" % args.mode.encode())
                time.sleep(0.3)
            except (serial.SerialException, OSError):
                pass  # a reboot is one of the ways this fails; the main loop reconnects
        # The channel list outlives this script, so always say what is wanted:
        # "CHANNELS 0" restores the firmware's own list and undoes an earlier --channels.
        cmd = b"CHANNELS %s\n" % (args.channels or "0").encode()
        if args.dwell is not None:
            cmd += b"DWELL %d\n" % args.dwell
        cmd += b"START %d %s\n" % (time.time_ns() // 1000, nonce)
        try:
            ser.write(cmd)
        except (serial.SerialException, OSError):
            pass  # board not listening, or the port just died: the main loop retries and reconnects
        last_start = time.monotonic()
        start_attempts += 1
        if start_attempts == 4:
            print("[!] The board does not answer START. Is the ESP-IDF firmware flashed? For the original "
                  "Arduino firmware use --no-handshake and press the reset button.")

    def finished(now):
        """True when the capture is over: Wireshark gone, Wireshark stopped reading, or --duration elapsed."""
        if proc is not None:
            if proc.poll() is not None or not sink.alive:
                print("[+] Wireshark was closed.")
                return True
            if sink.stalled():
                print("[+] Wireshark stopped reading (capture stopped?).")
                return True
        return bool(args.duration and sync_time is not None and now - sync_time >= args.duration)

    def forward(f, item):
        nonlocal proc, sink
        f.write(item)
        if wireshark and proc is None:
            print("[+] Starting up wireshark... (link type %d)" % framer.linktype)
            proc = launch_wireshark(wireshark, "ESP32 sniffer on " + args.port, profile, args.style)
            sink = PipeSink(proc)
            sink.start()
        if sink:
            sink.put(item)

    def process(f, data):
        nonlocal synced, start_attempts, sync_time, last_status
        just_lost = False
        while True:
            if not synced:
                data = scanner.feed(data, nonce)
                if data is None:
                    # no usable marker in what we have: ask the board for a fresh one
                    if just_lost and not args.no_handshake:
                        send_start()
                    return
                synced = True
                start_attempts = 0
                if sync_time is None:
                    sync_time = last_status = time.monotonic()
                    print("[+] Stream started...")
                else:
                    print("[+] Stream resynchronised.")
            for item in framer.feed(data):
                forward(f, item)
            if not framer.sync_lost:
                return
            # Wireshark only ever gets whole records, so it does not notice. Look for the next marker,
            # starting with the bytes that are already here.
            print("[!] Lost sync (%s), waiting for the next start marker..." % framer.sync_lost)
            synced = False
            just_lost = True
            data = framer.resync()

    try:
        with open(args.file, "wb") as f:
            while True:
                # (re)open the port; it can disappear for a moment when the board resets
                try:
                    if ser is None:
                        ser = open_serial(args.port, args.baud, reset_pending)
                        reset_pending = False
                        open_failures = 0
                        print("[+] Serial connected. Name: " + ser.name)
                        if not args.no_handshake:
                            send_start()
                        else:
                            print("[i] Waiting for <<START>>, press the reset button of the board if nothing happens.")
                    data = ser.read(ser.in_waiting or 1)
                except (serial.SerialException, OSError):
                    if ser is not None:
                        print("[!] Serial connection lost... Retrying...")
                        close_serial(ser)
                        ser = None
                        synced = False
                        framer.resync()  # a half received record is of no use
                        scanner.buf.clear()
                        open_failures = 0
                    else:
                        open_failures += 1
                        if open_failures in (1, 30) or open_failures % 300 == 0:
                            print("[!] Serial connection failed... Retrying..."
                                  + (" Is another program (idf.py monitor, a serial terminal, a second copy"
                                     " of this script) holding %s?" % args.port if open_failures >= 30 else ""))
                    time.sleep(1)
                    # also while the port is gone: --duration has to expire and a closed Wireshark to be noticed
                    if finished(time.monotonic()):
                        break
                    continue

                now = time.monotonic()
                if data:
                    bytes_in += len(data)
                    process(f, data)
                    f.flush()

                if not synced and not args.no_handshake and now - last_start > START_RETRY_S:
                    send_start()

                if sync_time is not None and now - last_status >= 5:
                    last_status = now
                    print("[i] %d packets, %.1f kB received%s" % (
                        framer.records, bytes_in / 1000,
                        ", %d not shown (Wireshark too slow)" % sink.dropped if sink and sink.dropped else ""),
                        flush=True)

                if finished(now):
                    break
    except KeyboardInterrupt:
        print("\n[+] Stopping...")
    finally:
        close_serial(ser)
        if sink is not None and sink.alive:
            try:
                sink.q.put_nowait(None)  # end of capture: closes Wireshark's stdin, the window stays open
            except queue.Full:
                pass
            sink.join(2)
            stuck = sink.is_alive()
        print("[+] Done. %d packets written to %s" % (framer.records, args.file))
    if stuck:
        try:
            sys.stdout.flush()  # os._exit() skips the flush the interpreter does when it shuts down
            sys.stderr.flush()
        except OSError:
            pass
        os._exit(0)  # the writer thread is blocked on a pipe nobody reads


if __name__ == "__main__":
    main()
