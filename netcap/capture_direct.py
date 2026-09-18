"""
Captura o trafego real do jogo direto na placa de rede (sem ExitLag),
filtrado pelo IP/porta do servidor, e salva tudo com timestamp -- pra
comparar com as capturas anteriores (via loopback/ExitLag) e ver se a
estrutura estranha (campo que muda mesmo parado) e do proprio jogo ou
era o ExitLag.

Uso: python netcap/capture_direct.py [segundos] [ip] [porta]
"""
import sys
import time

from scapy.all import sniff, TCP, IP, Raw

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 30
SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "51.79.37.183"
SERVER_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 55562
IFACE = "Ethernet"
OUT_PATH = "netcap/direct_capture.txt"

start_time = time.time()
rows = []


def handle(pkt):
    if TCP in pkt and IP in pkt and Raw in pkt:
        if pkt[IP].src == SERVER_IP or pkt[IP].dst == SERVER_IP:
            if pkt[TCP].sport == SERVER_PORT or pkt[TCP].dport == SERVER_PORT:
                payload = bytes(pkt[Raw].load)
                direction = "S->C" if pkt[TCP].sport == SERVER_PORT else "C->S"
                t = time.time() - start_time
                rows.append((t, direction, payload))


print(f"[captura] {DURATION}s direto em {SERVER_IP}:{SERVER_PORT} (iface={IFACE})...", flush=True)
sniff(iface=IFACE, filter=f"tcp and host {SERVER_IP} and port {SERVER_PORT}", prn=handle, timeout=DURATION, store=False)

with open(OUT_PATH, "w") as f:
    for t, direction, payload in rows:
        f.write(f"{t:.3f}\t{direction}\t{len(payload)}\t{payload.hex()}\n")

print(f"[ok] {len(rows)} pacotes salvos em {OUT_PATH}", flush=True)
