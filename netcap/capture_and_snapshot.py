"""
Roda a captura de pacotes do canal do jogo (56922 <-> 59507) e, em
paralelo, tira um recorte da regiao onde aparece a coordenada atual
("Event Square X, Y") a cada N segundos -- tudo com o mesmo relogio
(tempo relativo ao inicio), pra depois correlacionar qual pacote
C->S (comando de movimento) corresponde a qual coordenada de destino.

Uso: python netcap/capture_and_snapshot.py [segundos] [janela]
Enquanto roda: clique pra andar em varios lugares diferentes (perto),
espere o personagem chegar antes do proximo clique.
"""
import sys
import time
import threading
import os

import mss
import numpy as np
import cv2
import win32gui
from scapy.all import sniff, TCP, IP, Raw

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 90
WINDOW_TITLE = sys.argv[2] if len(sys.argv) > 2 else "InfowP"
IFACE = "Software Loopback Interface 1"
GAME_PORTS = {56922, 59507}
SNAPSHOT_INTERVAL = 2.0
OUT_DIR = "netcap/snaps"
OUT_PACKETS = "netcap/walk_capture2.txt"
# recorte relativo a janela do cliente, cobre o texto "Event Square 231, 34"
COORD_CROP = (0, 0, 320, 50)

os.makedirs(OUT_DIR, exist_ok=True)


def find_window(title_substring):
    title_substring = title_substring.lower()
    found = []
    def _callback(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        title = win32gui.GetWindowText(hwnd)
        if title and title_substring in title.lower():
            found.append(hwnd)
    win32gui.EnumWindows(_callback, None)
    return found[0] if found else None


def get_window_region(hwnd):
    left, top, right, bottom = win32gui.GetClientRect(hwnd)
    origin_x, origin_y = win32gui.ClientToScreen(hwnd, (left, top))
    return {"left": origin_x, "top": origin_y, "width": right - left, "height": bottom - top}


start_time = time.time()
rows = []


def handle(pkt):
    if TCP in pkt and IP in pkt and Raw in pkt:
        if pkt[TCP].sport in GAME_PORTS and pkt[TCP].dport in GAME_PORTS:
            payload = bytes(pkt[Raw].load)
            direction = "S->C" if pkt[TCP].sport == 56922 else "C->S"
            t = time.time() - start_time
            rows.append((t, direction, payload))


def sniff_thread():
    sniff(iface=IFACE, filter="tcp", prn=handle, timeout=DURATION, store=False)


def snapshot_loop():
    hwnd = find_window(WINDOW_TITLE)
    if hwnd is None:
        print(f"[erro] janela '{WINDOW_TITLE}' nao encontrada", flush=True)
        return
    sct = mss.mss()
    x0, y0, x1, y1 = COORD_CROP
    while time.time() - start_time < DURATION:
        t = time.time() - start_time
        region = get_window_region(hwnd)
        shot = np.array(sct.grab(region))
        crop = shot[y0:y1, x0:x1]
        cv2.imwrite(os.path.join(OUT_DIR, f"t_{t:06.2f}.png"), crop)
        time.sleep(SNAPSHOT_INTERVAL)


print(f"[captura] {DURATION}s -- clique pra andar em varios lugares diferentes, espere chegar entre cliques...", flush=True)

t1 = threading.Thread(target=sniff_thread)
t2 = threading.Thread(target=snapshot_loop)
t1.start()
t2.start()
t1.join()
t2.join()

with open(OUT_PACKETS, "w") as f:
    for t, direction, payload in rows:
        f.write(f"{t:.3f}\t{direction}\t{len(payload)}\t{payload.hex()}\n")

print(f"[ok] {len(rows)} pacotes salvos em {OUT_PACKETS}, snapshots em {OUT_DIR}/", flush=True)
