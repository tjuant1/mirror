"""
Para o grupo de pacotes S->C de tamanho mais comum, conta quantos
valores distintos aparecem em cada posicao de byte ao longo de TODA a
sessao. Uma posicao com poucos valores distintos (tipo 3-15) e uma
boa candidata a "id da entidade" (ou de um sub-tipo), diferente de
posicoes 100% constantes (sempre a mesma entidade/campo fixo) ou
posicoes com quase um valor distinto por pacote (ruido/nonce).
"""
import sys
from collections import defaultdict, Counter

PATH = sys.argv[1] if len(sys.argv) > 1 else "netcap/walk_capture2.txt"

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
print(f"Grupo dominante: len={dominant_len}, {len(group)} pacotes, t de {group[0][0]:.2f}s a {group[-1][0]:.2f}s\n", flush=True)

n = len(group)
print(f"{'pos':>4} | {'distintos':>9} | {'top valores:qtd'}", flush=True)
candidates = []
for pos in range(dominant_len):
    c = Counter(p[pos] for _, p in group)
    n_distinct = len(c)
    if 2 <= n_distinct <= 15:
        candidates.append((pos, n_distinct, c))

for pos, n_distinct, c in candidates:
    top = ",".join(f"{v:02x}:{q}" for v, q in c.most_common(6))
    print(f"{pos:4d} | {n_distinct:9d} | {top}", flush=True)
