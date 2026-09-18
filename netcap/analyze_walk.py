"""
Analisa netcap/walk_capture.txt: agrupa pacotes S->C pelo tamanho mais
comum, separa em duas metades por tempo (inicio vs fim da caminhada),
e mostra -- por posicao de byte -- quais valores apareceram em cada
metade. Um campo "de estado" (tipo coordenada) deve mostrar um cluster
de valores diferente em cada metade, com baixa variancia dentro de
cada uma. Um byte de ruido/nonce aparece espalhado em ambas as metades.
"""
import sys
from collections import defaultdict, Counter

PATH = sys.argv[1] if len(sys.argv) > 1 else "netcap/walk_capture.txt"

rows = []
with open(PATH) as f:
    for line in f:
        t, direction, length, hexstr = line.strip().split("\t")
        rows.append((float(t), direction, int(length), bytes.fromhex(hexstr)))

by_len = defaultdict(list)
for t, direction, length, payload in rows:
    if direction == "S->C":
        by_len[length].append((t, payload))

dominant_len = max(by_len, key=lambda k: len(by_len[k]))
group = sorted(by_len[dominant_len], key=lambda tp: tp[0])
print(f"Grupo dominante: len={dominant_len}, {len(group)} pacotes, t de {group[0][0]:.2f}s a {group[-1][0]:.2f}s", flush=True)

mid = len(group) // 2
first_half = [p for _, p in group[:mid]]
second_half = [p for _, p in group[mid:]]

print(f"\nPrimeira metade: {len(first_half)} pacotes | Segunda metade: {len(second_half)} pacotes\n", flush=True)

print(f"{'pos':>4} | {'1a metade (valores:qtd)':<45} | {'2a metade (valores:qtd)':<45} | overlap?", flush=True)
for pos in range(dominant_len):
    c1 = Counter(p[pos] for p in first_half)
    c2 = Counter(p[pos] for p in second_half)
    set1, set2 = set(c1), set(c2)
    overlap = len(set1 & set2)
    total_unique = len(set1 | set2)
    # so mostra posicoes "interessantes": poucos valores distintos por metade (baixa variancia)
    if len(set1) <= 4 and len(set2) <= 4:
        s1_txt = ",".join(f"{v:02x}:{n}" for v, n in c1.most_common(4))
        s2_txt = ",".join(f"{v:02x}:{n}" for v, n in c2.most_common(4))
        marker = "IGUAL" if set1 == set2 else ("muda" if overlap == 0 else "parcial")
        print(f"{pos:4d} | {s1_txt:<45} | {s2_txt:<45} | {marker}", flush=True)
