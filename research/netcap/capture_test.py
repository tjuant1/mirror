"""
Captura de teste: escuta todo trafego TCP na interface de loopback
(127.0.0.1) por alguns segundos, e mostra um resumo por conexao
(par de portas) + os primeiros bytes de alguns pacotes de cada uma,
pra gente identificar visualmente qual conexao carrega o protocolo
do jogo (MEGAMU <-> proxy local do ExitLag).

Uso: python netcap/capture_test.py [segundos]
Enquanto roda, mexa o personagem no jogo pra gerar trafego.
"""
import sys
from collections import defaultdict

from scapy.all import sniff, TCP, IP, Raw

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 15
IFACE = "Software Loopback Interface 1"

streams = defaultdict(lambda: {"count": 0, "bytes": 0, "samples": []})


def handle(pkt):
    if TCP in pkt and IP in pkt:
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        s = streams[key]
        s["count"] += 1
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            s["bytes"] += len(payload)
            if len(s["samples"]) < 3:
                s["samples"].append(payload)


print(f"[captura] ouvindo '{IFACE}' por {DURATION}s (filtro: tcp) -- mexa o personagem agora...", flush=True)
sniff(iface=IFACE, filter="tcp", prn=handle, timeout=DURATION, store=False)

print("\n=== RESUMO POR CONEXAO ===", flush=True)
for (src, sport, dst, dport), s in sorted(streams.items(), key=lambda kv: -kv[1]["bytes"]):
    print(f"\n{src}:{sport} -> {dst}:{dport}  | pacotes={s['count']} bytes_totais={s['bytes']}", flush=True)
    for i, sample in enumerate(s["samples"]):
        hexdump = sample[:64].hex(" ")
        print(f"  amostra {i} ({len(sample)} bytes): {hexdump}", flush=True)
