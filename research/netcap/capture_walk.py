"""
Captura o canal do jogo (56922 <-> 59507) durante uma caminhada em linha
reta, salvando TODOS os pacotes com timestamp relativo em um arquivo de
texto (hex por linha), pra dar pra analisar offline com mais calma do
que só as poucas amostras que o capture_diff.py mostra na tela.

Uso: python netcap/capture_walk.py [segundos] [arquivo_saida]
"""
import sys
import time

from scapy.all import sniff, TCP, IP, Raw

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 25
OUT_PATH = sys.argv[2] if len(sys.argv) > 2 else "netcap/walk_capture.txt"
IFACE = "Software Loopback Interface 1"
GAME_PORTS = {56922, 59507}

start_time = time.time()
rows = []


def handle(pkt):
    if TCP in pkt and IP in pkt and Raw in pkt:
        if pkt[TCP].sport in GAME_PORTS and pkt[TCP].dport in GAME_PORTS:
            payload = bytes(pkt[Raw].load)
            direction = "S->C" if pkt[TCP].sport == 56922 else "C->S"
            t = time.time() - start_time
            rows.append((t, direction, payload))


print(f"[captura] {DURATION}s -- ANDE AGORA em linha reta na direcao do NPC...", flush=True)
sniff(iface=IFACE, filter="tcp", prn=handle, timeout=DURATION, store=False)

with open(OUT_PATH, "w") as f:
    for t, direction, payload in rows:
        f.write(f"{t:.3f}\t{direction}\t{len(payload)}\t{payload.hex()}\n")

print(f"[ok] {len(rows)} pacotes salvos em {OUT_PATH}", flush=True)
