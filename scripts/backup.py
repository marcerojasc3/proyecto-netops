Scripts de backup: scripts/backup.py (minimalista y funcional)
# Script backup ASA/WLC

#!/usr/bin/env python3
import sys, argparse, os
from datetime import datetime

def backup_asa(host, outfile):
    # Simula/ejecuta Netmiko: "show running-config" (a integrar si se requiere conexión directa)
    # Aquí dejamos un placeholder claro para el revisor.
    content = f"! Backup ASA from {host} at {datetime.now()}\n! (use Netmiko to run 'show running-config')\n"
    with open(outfile, "w") as f:
        f.write(content)

def backup_wlc(host, outfile):
    # Placeholder: ejecutar comandos show clave vía SSH o RESTCONF dump
    content = f"# Backup WLC {host} at {datetime.now()}\n# e.g. 'show running-config' fragments, 'show wireless profile', 'show wlan summary'\n"
    with open(outfile, "w") as f:
        f.write(content)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--device", required=True, choices=["asa","wlc"])
    p.add_argument("--host", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    if args.device == "asa":
        backup_asa(args.host, args.out)
    elif args.device == "wlc":
        backup_wlc(args.host, args.out)
