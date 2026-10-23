#!/usr/bin/env python3
"""Accuracy and timing check against nmap -sT (the reference).

    python tests/compare_nmap.py [target] [ports]

Starts a few local listeners when the target is loopback so there is a known
answer, runs both scanners over the same ports, and prints any disagreement.
Exits 1 if the open-port sets differ. Needs nmap on PATH.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_nmap(target, ports):
    t = time.time()
    out = subprocess.run(["nmap", "-sT", "-Pn", "-n", "-p", ports, "-T4", "--open", target],
                         capture_output=True, text=True).stdout
    found = {int(m.group(1)) for m in re.finditer(r"^(\d+)/tcp\s+open", out, re.M)}
    return found, time.time() - t


def run_ours(target, ports):
    t = time.time()
    out = subprocess.run([sys.executable, os.path.join(ROOT, "port_scanner.py"),
                          target, "-p", ports],
                         capture_output=True, text=True, encoding="utf-8").stdout
    found = {int(m.group(1)) for m in re.finditer(r"^\[\+\] Port\s+(\d+)/tcp open", out, re.M)}
    return found, time.time() - t


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1024,20000-21999"
    if not shutil.which("nmap"):
        sys.exit("nmap not found on PATH")

    listeners = []
    if target in ("127.0.0.1", "localhost"):
        for port in (20003, 20500, 21001, 21500, 21999):  # inside the default range
            s = socket.socket()
            s.bind(("127.0.0.1", port))
            s.listen(16)
            listeners.append(s)
        print("local listeners:", sorted(s.getsockname()[1] for s in listeners))

    ref, ref_t = run_nmap(target, ports)
    ours, our_t = run_ours(target, ports)
    print(f"nmap -sT : {len(ref):3d} open  {ref_t:6.2f}s")
    print(f"ours     : {len(ours):3d} open  {our_t:6.2f}s")
    print("missed by ours  :", sorted(ref - ours) or "none")
    print("extra in ours   :", sorted(ours - ref) or "none")
    sys.exit(0 if ref == ours else 1)


if __name__ == "__main__":
    main()
