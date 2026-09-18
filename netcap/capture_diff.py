"""
Captura focada no canal real do jogo (56922 <-> 59507 no loopback) e
compara pacotes consecutivos de mesmo tamanho (do servidor pro cliente)
pra identificar quais posicoes de byte mudam -- esse e o jeito classico
de achar campos (como posicao x/y) mesmo dentro de dados ofuscados/
criptografados com XOR simples, sem precisar quebrar a cifra inteira.

Uso: python netcap/capture_diff.py [segundos]
Enquanto roda: ande em linha reta por uns segundos, pare, ande em outra
direcao, pare de novo. Isso gera pacotes parecidos entre si pra comparar.
"""
import sys
from collections import defaultdict

from scapy.all import sniff, TCP, IP, Raw

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 25
IFACE = "Software Loopback Interface 1"
GAME_PORTS = {56922, 59507}

packets_by_len = defaultdict(list)
all_packets = []


def handle(pkt):
    if TCP in pkt and IP in pkt and Raw in pkt:
        if pkt[TCP].sport in GAME_PORTS and pkt[TCP].dport in GAME_PORTS:
            payload = bytes(pkt[Raw].load)
            direction = "S->C" if pkt[TCP].sport == 56922 else "C->S"
            all_packets.append((direction, payload))
            packets_by_len[(direction, len(payload))].append(payload)


print(f"[captura] ouvindo canal do jogo por {DURATION}s -- ANDE em linha reta, pare, ande em outra direcao...", flush=True)
sniff(iface=IFACE, filter="tcp", prn=handle, timeout=DURATION, store=False)

print(f"\n=== {len(all_packets)} pacotes capturados no canal do jogo ===", flush=True)

print("\n=== Distribuicao de tamanhos (direcao, tamanho) -> quantidade ===", flush=True)
for (direction, length), pkts in sorted(packets_by_len.items(), key=lambda kv: -len(kv[1])):
    print(f"  {direction} len={length:4d}  count={len(pkts)}", flush=True)

print("\n=== Diffs entre pacotes consecutivos de mesmo tamanho (top grupos) ===", flush=True)
shown = 0
for (direction, length), pkts in sorted(packets_by_len.items(), key=lambda kv: -len(kv[1])):
    if len(pkts) < 3 or shown >= 4:
        continue
    shown += 1
    print(f"\n--- grupo {direction} len={length} ({len(pkts)} amostras) ---", flush=True)
    base = pkts[0]
    print(f"  base     : {base.hex(' ')}", flush=True)
    for idx, p in enumerate(pkts[1:6], start=1):
        diff_positions = [i for i in range(length) if p[i] != base[i]]
        print(f"  amostra{idx}: {p.hex(' ')}", flush=True)
        print(f"     bytes diferentes de base: {diff_positions}", flush=True)
