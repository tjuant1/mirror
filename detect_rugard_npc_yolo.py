"""
Detecta o NPC "Rugard" na tela de um aplicativo aberto usando um modelo YOLO
treinado (em vez de template matching) e clica nele assim que encontrado.

Uso:
    1. Preencha WINDOW_TITLE abaixo com um trecho do título da janela do jogo.
    2. Rode: python detect_rugard_npc_yolo.py
    3. Pressione F8 para ligar a varredura (e de novo para desligar).
    4. Enquanto ligado, fica procurando em loop. Ao encontrar o NPC com
       confianca suficiente, da um duplo clique nele e so aperta Enter se o
       dialogo de confirmacao ("DOPPELGANGER") realmente aparecer na tela.
    5. Depois de confirmar + Enter uma vez, essa janela nao tenta mais ate a
       proxima vez que voce ligar (F8) de novo -- evita clicar 2x na mesma
       tela (sucesso = trocou de mapa; falha = apareceu dialogo "OK").
    6. Ctrl+C encerra o script de vez.
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

WINDOW_TITLE = "SentelhaEl"  # trecho do título da janela do app/jogo
MODEL_PATH = "runs/detect/runs/rugard_v6/weights/best.pt"
CONF_THRESHOLD = 0.55  # confianca minima do YOLO pra aceitar a deteccao
IMG_SIZE = 832  # mesmo tamanho usado no treino
TOGGLE_KEY = win32con.VK_F8
MATCH_DEBUG_FILE = "last_match_debug.png"
EXCLUDE_BOTTOM_FRACTION = 0.13  # ignora a barra de habilidades/vida/mana no rodape
CLICK_COOLDOWN = 1.0  # segundos de pausa entre tentativas (so importa antes de confirmar)
REQUIRED_CONSECUTIVE_HITS = 2  # exige deteccao em N frames seguidos antes de clicar, filtra ruido de 1 frame so
CLICK_Y_BIAS = 0.65  # clica um pouco abaixo do centro da caixa (corpo/base), pois com as asas abertas o centro geometrico cai fora do NPC (area clicavel)

CONFIRM_TEMPLATE_PATH = "ui_templates/confirmation.png"
CONFIRM_MATCH_THRESHOLD = 0.55
CONFIRM_TIMEOUT = 1.0  # segundos esperando o dialogo aparecer apos o clique
CONFIRM_DEBUG_FILE = "confirm_debug.png"  # salvo sempre que a confirmacao falha, pra depuracao


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


def load_confirm_template(path):
    img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise RuntimeError(f"Nao consegui carregar o template de confirmacao em '{path}'")
    bgr = img[:, :, :3] if img.ndim == 3 and img.shape[2] == 4 else img
    return cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)


def confirmation_score(sct, region, template_gray):
    shot = np.array(sct.grab(region))
    frame_gray = cv2.cvtColor(shot, cv2.COLOR_BGRA2GRAY)
    if template_gray.shape[0] > frame_gray.shape[0] or template_gray.shape[1] > frame_gray.shape[1]:
        return -1.0, shot
    result = cv2.matchTemplate(frame_gray, template_gray, cv2.TM_CCOEFF_NORMED)
    result = np.nan_to_num(result, nan=-1.0, posinf=-1.0, neginf=-1.0)
    return float(result.max()), shot


def wait_for_confirmation(sct, region, template_gray, timeout=CONFIRM_TIMEOUT):
    deadline = time.time() + timeout
    best_score = -1.0
    best_shot = None
    while time.time() < deadline:
        score, shot = confirmation_score(sct, region, template_gray)
        if score > best_score:
            best_score, best_shot = score, shot
        if score >= CONFIRM_MATCH_THRESHOLD:
            print(f"[confirm] dialogo detectado (score={score:.3f})", flush=True)
            return True
        time.sleep(0.05)
    if best_shot is not None:
        cv2.imwrite(CONFIRM_DEBUG_FILE, cv2.cvtColor(best_shot, cv2.COLOR_BGRA2BGR))
    print(f"[confirm] dialogo NAO detectado (melhor score={best_score:.3f}, "
          f"limiar={CONFIRM_MATCH_THRESHOLD}) -- print salvo em {CONFIRM_DEBUG_FILE}", flush=True)
    return False


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
    print(f"[modelo] carregando {MODEL_PATH} ...", flush=True)
    model = YOLO(MODEL_PATH)
    confirm_template = load_confirm_template(CONFIRM_TEMPLATE_PATH)
    print("[modelo] pronto", flush=True)

    hwnd = find_window(WINDOW_TITLE)
    if hwnd is None:
        print(f"[erro] nenhuma janela encontrada com titulo contendo '{WINDOW_TITLE}'.", flush=True)
        print("Ajuste WINDOW_TITLE no topo do script para um trecho do titulo real da janela.", flush=True)
        sys.exit(1)
    print(f"[ok] janela encontrada: '{win32gui.GetWindowText(hwnd)}' (hwnd={hwnd})", flush=True)

    armed = False
    done = False  # trava apos confirmar+Enter uma vez, ate re-ligar
    toggle_state = {"was_pressed": False}
    sct = mss.mss()
    last_attempt_time = 0.0
    pending_hits = 0

    print("=" * 60, flush=True)
    print("F8 liga/desliga a varredura. Ctrl+C encerra de vez.", flush=True)
    print("=" * 60, flush=True)

    frame_count = 0
    last_fps_print = time.time()

    try:
        while True:
            if key_just_pressed(TOGGLE_KEY, toggle_state):
                armed = not armed
                if armed:
                    done = False
                    pending_hits = 0
                estado = ">>> VARREDURA LIGADA <<<" if armed else ">>> VARREDURA DESLIGADA <<<"
                print(estado, flush=True)

            if not armed or done:
                time.sleep(0.05)
                continue

            if not win32gui.IsWindow(hwnd):
                print("[erro] a janela alvo foi fechada.", flush=True)
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
                print(f"[debug] ~{fps:.1f} fps | melhor score atual: {score_txt}", flush=True)
                frame_count = 0
                last_fps_print = now

            if det and det["score"] >= CONF_THRESHOLD:
                pending_hits += 1
            else:
                pending_hits = 0

            if (det and det["score"] >= CONF_THRESHOLD and pending_hits >= REQUIRED_CONSECUTIVE_HITS
                    and (now - last_attempt_time) >= CLICK_COOLDOWN):
                last_attempt_time = now
                pending_hits = 0
                x0, y0, x1, y1 = det["bbox"]
                center_x = region["left"] + (x0 + x1) // 2
                center_y = region["top"] + y0 + round((y1 - y0) * CLICK_Y_BIAS)

                crop = shot[y0:y1, x0:x1]
                if crop.size > 0:
                    cv2.imwrite(MATCH_DEBUG_FILE, crop)

                print(f"[match] score={det['score']:.3f} em ({center_x}, {center_y}) "
                      f"| recorte salvo em {MATCH_DEBUG_FILE}", flush=True)
                double_click_at(center_x, center_y)

                if wait_for_confirmation(sct, region, confirm_template):
                    press_enter()
                    done = True
                    print("[ok] dialogo confirmado, Enter enviado. Essa tela nao tenta mais "
                          "ate a proxima vez que ligar (F8).", flush=True)
                else:
                    print("[aviso] clique nao mostrou o dialogo de confirmacao "
                          "(provavel falso positivo) -- Enter NAO enviado.", flush=True)
    except KeyboardInterrupt:
        print("\n[fim] interrompido pelo usuario.", flush=True)


if __name__ == "__main__":
    main()
