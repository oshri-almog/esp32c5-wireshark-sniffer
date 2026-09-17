"""Offline tests for the marker scanner and PCAP framer. No serial port, no Wireshark needed.

    python tests/test_pcap_framing.py
"""
import importlib.util
import os
import random
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("sniffer", os.path.join(REPO, "host", "sniffer.py"))
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)

GLOBAL = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)


def rec(i, n):
    payload = bytes((i + k) & 0xFF for k in range(n))
    return struct.pack("<IIII", 1700000000 + i, (i * 1237) % 1000000, n, n) + payload


def run(stream, nonce, chunk, handshake=True):
    """Mimics SerialShark.process(): returns (items, n_synclost)."""
    scanner, framer = ss.MarkerScanner(), ss.PcapFramer()
    synced, items, lost = False, [], 0
    for off in range(0, len(stream), chunk):
        data = stream[off:off + chunk]
        while True:
            if not synced:
                data = scanner.feed(data, nonce)
                if data is None:
                    break
                synced = True
            items += framer.feed(data)
            if not framer.sync_lost:
                break
            lost += 1
            synced = False
            data = framer.resync()
    return items, lost


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        sys.exit(1)


recs = [rec(i, 40 + (i * 37) % 900) for i in range(60)]
# payloads deliberately contain 0x0A / 0x0D / marker-like bytes
recs[5] = rec(5, 64)[:16] + b"<<START>>\n" + bytes(54)
recs[5] = struct.pack("<IIII", 5, 5, 64, 64) + recs[5][16:]

for chunk in (1, 3, 7, 11, 64, 4096, 1 << 20):
    # 1. clean start, plain marker (legacy mode)
    s = b"ESP-ROM:esp32c5-eco2\r\nboot text\r\n\n<<START>>\n" + GLOBAL + b"".join(recs[:5] + recs[6:])
    items, lost = run(s, None, chunk)
    check("plain marker chunk=%d" % chunk, items == [GLOBAL] + recs[:5] + recs[6:] and lost == 0)

    # 2. CRLF marker (Arduino println)
    s = b"\r\n<<START>>\r\n" + GLOBAL + b"".join(recs[:10])
    items, lost = run(s, None, chunk)
    check("CRLF marker chunk=%d" % chunk, items == [GLOBAL] + recs[:10] and lost == 0)

    # 3. handshake: stale records + stale boot marker + stale header, then OUR marker
    stale = b"".join(recs[20:30]) + b"\n<<START>>\n" + GLOBAL + b"".join(recs[30:40])
    s = stale + b"\n<<START>> deadbeef\n" + GLOBAL + b"".join(recs[:10])
    items, lost = run(s, b"deadbeef", chunk)
    check("nonce skips stale marker chunk=%d" % chunk, items == [GLOBAL] + recs[:10] and lost == 0)

    # 4. wrong nonce is never accepted
    items, lost = run(b"\n<<START>> 0badc0de\n" + GLOBAL + b"".join(recs[:3]), b"deadbeef", chunk)
    check("wrong nonce ignored chunk=%d" % chunk, items == [] and lost == 0)

    # 5. legacy mode: board reboots mid-stream (partial record, boot text, new marker + header)
    s = (b"\n<<START>>\n" + GLOBAL + b"".join(recs[:10]) + recs[10][:30]
         + b"ESP-ROM:esp32c5\r\nrst:0x15\r\n" + b"\n<<START>>\n" + GLOBAL + b"".join(recs[40:50]))
    items, lost = run(s, None, chunk)
    ok = items[0] == GLOBAL and items.count(GLOBAL) == 1 and items[1:11] == recs[:10] and items[-10:] == recs[40:50]
    check("reboot mid-stream resyncs, one global header chunk=%d (lost=%d, extra=%d)"
          % (chunk, lost, len(items) - 21), ok and lost >= 1)

    # 6. second marker + header right at a record boundary (duplicate START answer)
    s = (b"\n<<START>>\n" + GLOBAL + b"".join(recs[:10]) + b"\n<<START>>\n" + GLOBAL + b"".join(recs[40:50]))
    items, lost = run(s, None, chunk)
    check("marker at record boundary chunk=%d" % chunk,
          items == [GLOBAL] + recs[:10] + recs[40:50] and lost == 1)

# 7. random garbage never yields items
random.seed(1)
garbage = bytes(random.getrandbits(8) for _ in range(200000))
items, lost = run(garbage, None, 4096)
check("random garbage yields nothing", items == [])

# 8. record containing the marker text inside its payload is forwarded intact when synced
s = b"\n<<START>>\n" + GLOBAL + b"".join(recs[:10])
items, lost = run(s, None, 17)
check("marker text inside payload", items == [GLOBAL] + recs[:10] and lost == 0)

print("ALL OK")

