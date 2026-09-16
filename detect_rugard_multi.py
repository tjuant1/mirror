"""
Versao multi-conta: varre as janelas de N contas em busca do NPC "Rugard" e,
assim que uma delas encontra o NPC, clica nele (duplo clique + Enter) de
forma totalmente independente por conta -- entrar em party e usar o "mover
ate o membro" NAO funciona para entrar no evento, entao cada conta precisa
clicar no NPC por conta propria na sua propria tela.

Uso:
    1. Preencha ACCOUNTS abaixo com as contas que o script deve monitorar.
    2. Rode: python detect_rugard_multi.py
    3. Pressione F8 para ligar (e de novo para desligar). Ctrl+C encerra de vez.
"""

import os
import sys
import time

import cv2
import numpy as np
import mss
import win32api
import win32con
import win32gui
from ultralytics import YOLO

# Nomes = trecho do titulo da janela de cada conta que o script deve
# monitorar e clicar de forma independente (a 3a conta, se houver, entra
# manualmente e nao e controlada por este script).
ACCOUNTS = ["InfowP", "SentelhaEl"]

MODEL_PATH = "runs/detect/runs/rugard_v6/weights/best.pt"
CONF_THRESHOLD = 0.55
IMG_SIZE = 832
TOGGLE_KEY = win32con.VK_F8
EXCLUDE_BOTTOM_FRACTION = 0.13
CLICK_COOLDOWN = 1.0  # por conta, evita clicar varias vezes seguidas no mesmo NPC
REQUIRED_CONSECUTIVE_HITS = 2  # exige deteccao em N frames seguidos antes de clicar, filtra ruido de 1 frame so
CLICK_Y_BIAS = 0.65  # clica um pouco abaixo do centro da caixa (corpo/base), pois com as asas abertas o centro geometrico cai fora do NPC (area clicavel)
MATCH_DEBUG_DIR = "last_match_debug"

# Dialogo "DOPPELGANGER / Voce tem um Mirror of Dimensions..." que aparece
# so quando o clique realmente acertou o NPC. So apertamos Enter se esse
# dialogo realmente aparecer na tela -- assim nunca "erramos" um Enter pra
# dentro do chat quando o clique foi falso.
CONFIRM_TEMPLATE_PATH = "ui_templates/confirmation.png"
CONFIRM_MATCH_THRESHOLD = 0.55
CONFIRM_TIMEOUT = 1.0  # segundos esperando o dialogo aparecer apos o clique
CONFIRM_DEBUG_FILE = "confirm_debug.png"  # salvo sempre que a confirmacao falha, pra depuracao
DEBUG_CONF_FLOOR = 0.1  # so pra enxergar o score real do YOLO mesmo abaixo do CONF_THRESHOLD (diagnostico)
DEBUG_PRINT_INTERVAL = 2.0  # segundos entre prints de "melhor score atual" por conta


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


def wait_for_confirmation(sct, region, template_gray, account_name, timeout=CONFIRM_TIMEOUT):
    deadline = time.time() + timeout
    best_score = -1.0
    best_shot = None
    while time.time() < deadline:
        score, shot = confirmation_score(sct, region, template_gray)
        if score > best_score:
            best_score, best_shot = score, shot
        if score >= CONFIRM_MATCH_THRESHOLD:
            print(f"[confirm] {account_name}: dialogo detectado (score={score:.3f})", flush=True)
            return True
        time.sleep(0.05)
    if best_shot is not None:
        cv2.imwrite(CONFIRM_DEBUG_FILE, cv2.cvtColor(best_shot, cv2.COLOR_BGRA2BGR))
    print(f"[confirm] {account_name}: dialogo NAO detectado (melhor score={best_score:.3f}, "
          f"limiar={CONFIRM_MATCH_THRESHOLD}) -- print salvo em {CONFIRM_DEBUG_FILE}", flush=True)
    return False


def best_detection(model, frame_bgr, conf=CONF_THRESHOLD):
    results = model.predict(frame_bgr, conf=conf, imgsz=IMG_SIZE, verbose=False)
    boxes = results[0].boxes
    if len(boxes) == 0:
        return None
    best_idx = int(boxes.conf.argmax())
    x0, y0, x1, y1 = boxes.xyxy[best_idx].tolist()
    score = float(boxes.conf[best_idx])
    return {"score": score, "bbox": (round(x0), round(y0), round(x1), round(y1))}


def main():
    print(f"[modelo] carregando {MODEL_PATH} ...", flush=True)
    model = YOLO(MODEL_PATH)
    confirm_template = load_confirm_template(CONFIRM_TEMPLATE_PATH)
    print("[modelo] pronto", flush=True)

    windows = {}
    for name in ACCOUNTS:
        hwnd = find_window(name)
        if hwnd is None:
            print(f"[erro] nenhuma janela encontrada com titulo contendo '{name}'.", flush=True)
            sys.exit(1)
        windows[name] = hwnd
        print(f"[ok] '{name}' -> '{win32gui.GetWindowText(hwnd)}' (hwnd={hwnd})", flush=True)

    os.makedirs(MATCH_DEBUG_DIR, exist_ok=True)
    sct = mss.mss()
    armed = False
    toggle_state = {"was_pressed": False}
    last_click_time = {name: 0.0 for name in ACCOUNTS}
    pending_hits = {name: 0 for name in ACCOUNTS}
    done_accounts = set()  # contas que ja confirmaram+enviaram Enter nesta sessao (nunca clicam de novo ate re-ligar)
    last_debug_print = {name: 0.0 for name in ACCOUNTS}

    print("=" * 60, flush=True)
    print("F8 e GLOBAL: aperte 1 vez so (em qualquer janela) pra ligar,", flush=True)
    print("e de novo (1 vez) pra desligar. Ctrl+C encerra de vez.", flush=True)
    print("=" * 60, flush=True)

    try:
        while True:
            if key_just_pressed(TOGGLE_KEY, toggle_state):
                armed = not armed
                if armed:
                    done_accounts.clear()
                    for k in pending_hits:
                        pending_hits[k] = 0
                estado = ">>> VARREDURA LIGADA <<<" if armed else ">>> VARREDURA DESLIGADA <<<"
                print(estado, flush=True)

            if not armed:
                time.sleep(0.05)
                continue

            for name in ACCOUNTS:
                if name in done_accounts:
                    continue

                hwnd = windows[name]
                if not win32gui.IsWindow(hwnd):
                    print(f"[erro] a janela de '{name}' foi fechada.", flush=True)
                    sys.exit(1)

                region = get_window_region(hwnd)
                if region["width"] <= 0 or region["height"] <= 0:
                    continue

                shot = np.array(sct.grab(region))
                search_h = round(shot.shape[0] * (1.0 - EXCLUDE_BOTTOM_FRACTION))
                frame_bgr = cv2.cvtColor(shot[:search_h], cv2.COLOR_BGRA2BGR)

                det = best_detection(model, frame_bgr, conf=DEBUG_CONF_FLOOR)

                now_dbg = time.time()
                if now_dbg - last_debug_print[name] >= DEBUG_PRINT_INTERVAL:
                    score_txt = f"{det['score']:.2f}" if det else "-"
                    print(f"[debug] {name}: melhor score atual: {score_txt}", flush=True)
                    last_debug_print[name] = now_dbg

                if det and det["score"] >= CONF_THRESHOLD:
                    pending_hits[name] += 1
                else:
                    pending_hits[name] = 0
                    continue
                if pending_hits[name] < REQUIRED_CONSECUTIVE_HITS:
                    continue
                if time.time() - last_click_time[name] < CLICK_COOLDOWN:
                    continue
                pending_hits[name] = 0

                x0, y0, x1, y1 = det["bbox"]
                center_x = region["left"] + (x0 + x1) // 2
                center_y = region["top"] + y0 + round((y1 - y0) * CLICK_Y_BIAS)

                crop = shot[y0:y1, x0:x1]
                if crop.size > 0:
                    cv2.imwrite(os.path.join(MATCH_DEBUG_DIR, f"{name}.png"), crop)

                print(f"[match] {name}: score={det['score']:.3f} em ({center_x}, {center_y})", flush=True)
                double_click_at(center_x, center_y)
                last_click_time[name] = time.time()

                if wait_for_confirmation(sct, region, confirm_template, name):
                    press_enter()
                    done_accounts.add(name)
                    print(f"[ok] {name}: dialogo confirmado, Enter enviado. "
                          f"Essa conta nao tenta mais ate a proxima vez que ligar (F8).", flush=True)
                else:
                    print(f"[aviso] {name}: clique nao mostrou o dialogo de confirmacao "
                          f"(provavel falso positivo) -- Enter NAO enviado.", flush=True)

            time.sleep(0.02)
    except KeyboardInterrupt:
        print("\n[fim] interrompido pelo usuario.", flush=True)


if __name__ == "__main__":
    main()
