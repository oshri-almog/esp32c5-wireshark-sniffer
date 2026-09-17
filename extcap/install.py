#!/usr/bin/env python3
"""Register the sniffer with Wireshark, so the boards appear in its interface list.

    python extcap/install.py            install (or update) it
    python extcap/install.py --remove   take it out again

Only a small launcher is copied into Wireshark's extcap folder; the plugin itself stays in this
repository, so a `git pull` is enough to update it. Wireshark on Windows only runs programs it can
execute directly, which is why the launcher is a .bat and not the .py file.
"""

import argparse
import os
import shutil
import subprocess
import sys

NAME = "esp32_sniffer"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(REPO, "extcap", NAME + ".py")

PROFILE_NAME = "WLAN-detail"
PROFILE_SRC = os.path.join(REPO, "wireshark", "profiles", PROFILE_NAME)


def extcap_dirs():
    """Where Wireshark looks for extcap programs, personal folder first."""
    dirs = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            dirs.append(os.path.join(appdata, "Wireshark", "extcap"))
        for var in ("ProgramW6432", "ProgramFiles"):
            if os.environ.get(var):
                dirs.append(os.path.join(os.environ[var], "Wireshark", "extcap"))
    else:
        home = os.path.expanduser("~")
        dirs.append(os.path.join(home, ".config", "wireshark", "extcap"))
        dirs.append(os.path.join(home, ".local", "lib", "wireshark", "extcap"))
    return dirs


def launcher_path(directory):
    return os.path.join(directory, NAME + (".bat" if sys.platform == "win32" else ""))


def profiles_dir():
    if sys.platform == "win32":
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Wireshark")
    else:
        base = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "wireshark")
    return os.path.join(base, "profiles")


def install_profile(force=False):
    """Put the WLAN-detail Wireshark profile in place: the columns, colours and Wi-Fi filter buttons."""
    if not os.path.isdir(PROFILE_SRC):
        print("[!] No profile in the repository at %s" % PROFILE_SRC)
        return None
    dest = os.path.join(profiles_dir(), PROFILE_NAME)
    if os.path.isdir(dest) and not force:
        print("[i] Wireshark profile '%s' is already there, left untouched." % PROFILE_NAME)
        print("    Use --force-profile to overwrite it with the one from this repository.")
        return PROFILE_NAME
    os.makedirs(dest, exist_ok=True)
    for name in sorted(os.listdir(PROFILE_SRC)):
        src = os.path.join(PROFILE_SRC, name)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(dest, name))
    print("[+] Installed Wireshark profile '%s' (%s)" % (PROFILE_NAME, dest))
    return PROFILE_NAME


def install():
    directory = extcap_dirs()[0]
    os.makedirs(directory, exist_ok=True)
    path = launcher_path(directory)

    if sys.platform == "win32":
        # The full path to python.exe: Wireshark does not necessarily inherit a useful PATH.
        body = '@echo off\r\n"%s" "%s" %%*\r\n' % (sys.executable, PLUGIN)
        with open(path, "w", newline="") as f:
            f.write(body)
    else:
        with open(path, "w", newline="\n") as f:
            f.write('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, PLUGIN))
        os.chmod(path, 0o755)

    print("[+] Installed %s" % path)
    print("    -> %s" % PLUGIN)
    return path


def remove():
    gone = False
    for directory in extcap_dirs():
        path = launcher_path(directory)
        if os.path.isfile(path):
            os.remove(path)
            print("[+] Removed %s" % path)
            gone = True
    if not gone:
        print("[i] Nothing to remove.")


def verify():
    """Ask Wireshark itself whether it can see the boards now."""
    tshark = shutil.which("tshark")
    if not tshark and sys.platform == "win32":
        for var in ("ProgramW6432", "ProgramFiles"):
            candidate = os.path.join(os.environ.get(var, ""), "Wireshark", "tshark.exe")
            if os.path.isfile(candidate):
                tshark = candidate
                break
    if not tshark:
        print("[i] tshark not found, skipping the check.")
        return
    try:
        listing = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError) as e:
        print("[!] Could not run tshark: %s" % e)
        return
    found = [line for line in listing.splitlines() if "ESP32" in line]
    if found:
        print("[+] Wireshark can see:")
        for line in found:
            print("      " + line.strip())
        print("[i] In Wireshark press F5 (Capture -> Refresh Interfaces) if they are not in the list yet.")
    else:
        print("[!] Wireshark does not list any ESP32 yet. Is a board plugged in?")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remove", action="store_true", help="uninstall instead of installing")
    ap.add_argument("--no-profile", action="store_true", help="do not install the Wireshark profile")
    ap.add_argument("--force-profile", action="store_true",
                    help="overwrite an existing '%s' profile with the one from this repository"
                         % PROFILE_NAME)
    args = ap.parse_args()
    if args.remove:
        remove()
    else:
        install()
        if not args.no_profile:
            install_profile(force=args.force_profile)
        verify()
