"""
Detecta o NPC "Rugard" na tela de um aplicativo aberto usando um modelo YOLO
treinado (em vez de template matching) e clica nele assim que encontrado.

Uso:
    1. Preencha WINDOW_TITLE abaixo com um trecho do título da janela do jogo.
    2. Rode: python detect_rugard_npc_yolo.py
    3. Pressione F8 para ligar a varredura (e de novo para desligar).
    4. Enquanto ligado, fica procurando em loop. Toda vez que encontrar o NPC
       com confiança suficiente, dá um duplo clique nele, espera 0.5s,
       pressiona Enter, e continua procurando (não encerra sozinho).
    5. Ctrl+C encerra o script de vez.
"""

import sys
import time

import cv2
import numpy as np
import mss
import win32api
import win32con
import win32gui
from ultralytics import YOLO

WINDOW_TITLE = "InfowP"  # trecho do título da janela do app/jogo
MODEL_PATH = "runs/detect/runs/rugard_v4/weights/best.pt"
CONF_THRESHOLD = 0.55  # confianca minima do YOLO pra aceitar a deteccao (real ficou 0.6-0.92 nos testes, ruido/falso-positivo chegou a 0.43)
IMG_SIZE = 832  # mesmo tamanho usado no treino
TOGGLE_KEY = win32con.VK_F8
MATCH_DEBUG_FILE = "last_match_debug.png"
EXCLUDE_BOTTOM_FRACTION = 0.13  # ignora a barra de habilidades/vida/mana no rodape
CLICK_COOLDOWN = 1.0  # segundos de pausa apos um clique, pra nao clicar varias vezes seguidas no mesmo NPC


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


def best_detection(model, frame_bgr):
    results = model.predict(frame_bgr, conf=CONF_THRESHOLD, imgsz=IMG_SIZE, verbose=False)
    boxes = results[0].boxes
    if len(boxes) == 0:
        return None
    best_idx = int(boxes.conf.argmax())
    x0, y0, x1, y1 = boxes.xyxy[best_idx].tolist()
    score = float(boxes.conf[best_idx])
    return {"score": score, "bbox": (round(x0), round(y0), round(x1), round(y1))}


def click_at(x, y):
    win32api.SetCursorPos((x, y))
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)


def double_click_at(x, y):
    click_at(x, y)
    time.sleep(0.08)
    click_at(x, y)


def press_enter():
    win32api.keybd_event(win32con.VK_RETURN, 0, 0, 0)
    time.sleep(0.03)
    win32api.keybd_event(win32con.VK_RETURN, 0, win32con.KEYEVENTF_KEYUP, 0)


def key_just_pressed(vk_code, state):
    pressed = win32api.GetAsyncKeyState(vk_code) & 0x8000 != 0
    edge = pressed and not state["was_pressed"]
    state["was_pressed"] = pressed
    return edge


def main():
    print(f"[modelo] carregando {MODEL_PATH} ...")
    model = YOLO(MODEL_PATH)
    print("[modelo] pronto")

    hwnd = find_window(WINDOW_TITLE)
    if hwnd is None:
        print(f"[erro] nenhuma janela encontrada com titulo contendo '{WINDOW_TITLE}'.")
        print("Ajuste WINDOW_TITLE no topo do script para um trecho do titulo real da janela.")
        sys.exit(1)
    print(f"[ok] janela encontrada: '{win32gui.GetWindowText(hwnd)}' (hwnd={hwnd})")

    armed = False
    toggle_state = {"was_pressed": False}
    sct = mss.mss()

    print("Pressione F8 para ligar a varredura (e de novo para desligar). Ctrl+C encerra de vez.")

    frame_count = 0
    last_fps_print = time.time()

    try:
        while True:
            if key_just_pressed(TOGGLE_KEY, toggle_state):
                armed = not armed
                print(f"[status] varredura {'LIGADA' if armed else 'DESLIGADA'}")

            if not armed:
                time.sleep(0.05)
                continue

            if not win32gui.IsWindow(hwnd):
                print("[erro] a janela alvo foi fechada.")
                sys.exit(1)

            region = get_window_region(hwnd)
            if region["width"] <= 0 or region["height"] <= 0:
                time.sleep(0.05)
                continue

            shot = np.array(sct.grab(region))
            search_h = round(shot.shape[0] * (1.0 - EXCLUDE_BOTTOM_FRACTION))
            frame_bgr = cv2.cvtColor(shot[:search_h], cv2.COLOR_BGRA2BGR)

            det = best_detection(model, frame_bgr)
            frame_count += 1

            now = time.time()
            if now - last_fps_print >= 2:
                fps = frame_count / (now - last_fps_print)
                score_txt = f"{det['score']:.2f}" if det else "-"
                print(f"[debug] ~{fps:.1f} fps | melhor score atual: {score_txt}")
                frame_count = 0
                last_fps_print = now

            if det and det["score"] >= CONF_THRESHOLD:
                x0, y0, x1, y1 = det["bbox"]
                center_x = region["left"] + (x0 + x1) // 2
                center_y = region["top"] + (y0 + y1) // 2

                crop = shot[y0:y1, x0:x1]
                if crop.size > 0:
                    cv2.imwrite(MATCH_DEBUG_FILE, crop)

                print(f"[match] score={det['score']:.3f} em ({center_x}, {center_y}) "
                      f"| recorte salvo em {MATCH_DEBUG_FILE}")
                double_click_at(center_x, center_y)
                time.sleep(0.5)
                press_enter()
                print(f"[ok] duplo clique + Enter realizados. Pausando {CLICK_COOLDOWN:.0f}s antes de continuar a varredura.")
                cooldown_until = time.time() + CLICK_COOLDOWN
                while time.time() < cooldown_until:
                    if key_just_pressed(TOGGLE_KEY, toggle_state):
                        armed = not armed
                        print(f"[status] varredura {'LIGADA' if armed else 'DESLIGADA'}")
                    time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n[fim] interrompido pelo usuario.")


if __name__ == "__main__":
    main()
