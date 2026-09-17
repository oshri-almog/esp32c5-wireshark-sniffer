"""Feed the plugin the exact bytes Wireshark's toolbar sends, and check what it does.

    python tests/test_control_pipe.py
"""
import importlib.util, os, struct, sys, tempfile, threading, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "plug", os.path.join(REPO, "extcap", "esp32_sniffer.py"))
plug = importlib.util.module_from_spec(spec); spec.loader.exec_module(plug)


def frame(control, command, payload=b""):
    """The wire format Wireshark uses on the control pipe."""
    return struct.pack(">sBHBB", b"T", 0, len(payload) + 2, control, command) + payload


tmp = tempfile.mkdtemp()
in_path = os.path.join(tmp, "ctrl_in")
out_path = os.path.join(tmp, "ctrl_out")

# Build the byte stream Wireshark would send: initialise, pick a preset, type a custom list, press Apply
stream = b"".join([
    frame(0, plug.CMD_INITIALIZED),
    frame(plug.CTRL_PRESET, plug.CMD_SET, b"11"),                 # preset -> applies at once
    frame(plug.CTRL_CHANNELS, plug.CMD_SET, b"1-5"),              # typed text -> waits
    frame(plug.CTRL_DWELL, plug.CMD_SET, b"120"),                 # typed text -> waits
    frame(plug.CTRL_APPLY, plug.CMD_SET, b""),                    # Apply -> both are sent
    frame(plug.CTRL_CHANNELS, plug.CMD_SET, b"999"),              # invalid -> must be refused
    frame(plug.CTRL_APPLY, plug.CMD_SET, b""),
])
with open(in_path, "wb") as f:
    f.write(stream)
open(out_path, "wb").close()

seen = []
cp = plug.ControlPipes(in_path, out_path, on_change=lambda k, v: seen.append((k, v)))
cp.start()
time.sleep(1.0)
cp.running = False

print("changes the plugin acted on:")
for k, v in seen:
    print("   %-12s %r" % (k, v))

expected = [("initialized", None), ("channels", "11"), ("channels", "1-5"), ("dwell", "120"),
            ("channels", "999")]
ok = seen == expected
print("\nparsed control stream correctly:", ok)
if not ok:
    print("expected:", expected)

# and the status writes we send back must be valid frames
cp2 = plug.ControlPipes(None, out_path, on_change=lambda k, v: None)
cp2.status("COM14 | channels 1-5 | 120 ms")
data = open(out_path, "rb").read()
sync, pad, length, control, command = struct.unpack(">sBHBB", data[:6])
payload = data[6:6 + length - 2]
print("status frame -> sync=%r control=%d command=%d payload=%r" % (sync, control, command, payload))
print("status frame well formed:", sync == b"T" and control == plug.CTRL_STATUS
      and command == plug.CMD_SET and payload == b"COM14 | channels 1-5 | 120 ms")

