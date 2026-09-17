"""The channel parser has to read a spec in the numbering of the radio it is for.

Wi-Fi and 802.15.4 both have channels 11 to 14 and they are not the same channels, so a spec means
nothing without a radio to read it against. Getting this wrong is quiet rather than loud: "11-26"
used to come back as 11, 12, 13, 14 for an 802.15.4 capture, and the capture ran happily on four
channels out of sixteen.
"""
import importlib.util
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ss = _load("sniffer", os.path.join(REPO, "host", "sniffer.py"))
sys.path.insert(0, os.path.join(REPO, "extcap"))
ex = _load("esp32_sniffer", os.path.join(REPO, "extcap", "esp32_sniffer.py"))

ACCEPT = [
    ("6", "wifi", [6]),
    ("1,6,11", "wifi", [1, 6, 11]),
    ("1-11", "wifi", list(range(1, 12))),
    ("36-48", "wifi", [36, 40, 44, 48]),
    ("1-13,36,149-165", "wifi",
     list(range(1, 14)) + [36, 149, 153, 157, 161, 165]),
    ("11-26", "802154", list(range(11, 27))),
    ("20", "802154", [20]),
    ("15,20,25", "802154", [15, 20, 25]),
    ("11", "802154", [11]),
]

REJECT = [("20", "wifi"), ("27", "802154"), ("10", "802154"), ("37", "wifi")]

# What the settings dialog, the toolbar and the command line each hand to the plugin
EXTCAP = [
    ("11-26", "802154", list(range(11, 27))),
    ("g154,20", "802154", [20]),
    ("1,6,11", "wifi", [1, 6, 11]),
    ("20", "802154", [20]),
]


def main():
    failures = 0

    for spec, mode, expected in ACCEPT:
        got = ss.parse_channel_spec(spec, mode)
        if got == expected:
            print("PASS %-16s %-7s -> %s" % (spec, mode, got))
        else:
            failures += 1
            print("FAIL %-16s %-7s -> %s, wanted %s" % (spec, mode, got, expected))

    for spec, mode in REJECT:
        try:
            got = ss.parse_channel_spec(spec, mode)
            failures += 1
            print("FAIL %-16s %-7s -> %s, should have been refused" % (spec, mode, got))
        except ValueError:
            print("PASS %-16s %-7s refused" % (spec, mode))

    for raw, mode, expected in EXTCAP:
        got = (ex.channels_from_ticks(raw, mode)
               or [c for c in ex.parse_channel_spec_safe(raw, mode) if ex.channel_ok_for(mode, c)])
        if got == expected:
            print("PASS extcap %-9s %-7s -> %s" % (raw, mode, got))
        else:
            failures += 1
            print("FAIL extcap %-9s %-7s -> %s, wanted %s" % (raw, mode, got, expected))

    print("ALL OK" if not failures else "%d FAILURES" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
