"""
Detecta o NPC "Rugard" (armadura cinza, sentado, asa branca) na tela de um
aplicativo aberto e clica nele assim que encontrado.

Uso:
    1. Preencha WINDOW_TITLE abaixo com um trecho do título da janela do jogo.
    2. Rode: python detect_rugard_npc.py
    3. Pressione F8 para ligar a varredura (e de novo para pausar).
    4. Assim que o NPC for encontrado com confiança suficiente, o script
       clica nele e encerra.
"""

import glob
import os
import sys
import time

import cv2
import numpy as np
import mss
import win32api
import win32con
import win32gui

WINDOW_TITLE = "InfowP"  # trecho do título da janela do app/jogo
TEMPLATE_DIR = "img-rugard"
MATCH_THRESHOLD = 0.65
TOGGLE_KEY = win32con.VK_F8
DEBUG_SHOW = False  # True mostra uma janela com o bounding box do melhor match (mais lento, útil só pra calibrar)
DOWNSCALE = 0.6  # busca em resolução reduzida (muito mais rápido, e reduz ruído de amostragem); baixe mais (ex 0.4) se ainda estiver lento, ou suba se estiver perdendo o NPC
MATCH_DEBUG_FILE = "last_match_debug.png"  # recorte salvo a cada match aceito, pra conferir visualmente se era o NPC mesmo
EXCLUDE_BOTTOM_FRACTION = 0.13  # ignora essa fração inferior da janela (barra de habilidades/vida/mana) pra nunca casar com HUD fixo


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


def load_templates(template_dir, scale=1.0):
    templates = []
    paths = sorted(glob.glob(os.path.join(template_dir, "*.png")))
    if not paths:
        raise RuntimeError(f"Nenhum template .png encontrado em '{template_dir}'")

    for path in paths:
        img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
        if img is None:
            print(f"[aviso] nao consegui carregar {path}, ignorando")
            continue

        mask = None
        if img.ndim == 3 and img.shape[2] == 4:
            alpha = img[:, :, 3]
            if alpha.min() < 255:
                mask = alpha
            gray = cv2.cvtColor(img[:, :, :3], cv2.COLOR_BGR2GRAY)
        elif img.ndim == 3:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        else:
            gray = img

        if scale != 1.0:
            new_w = max(1, round(gray.shape[1] * scale))
            new_h = max(1, round(gray.shape[0] * scale))
            gray = cv2.resize(gray, (new_w, new_h), interpolation=cv2.INTER_AREA)
            if mask is not None:
                mask = cv2.resize(mask, (new_w, new_h), interpolation=cv2.INTER_NEAREST)

        method = cv2.TM_CCORR_NORMED if mask is not None else cv2.TM_CCOEFF_NORMED
        templates.append({"name": os.path.basename(path), "gray": gray, "mask": mask, "method": method})
        mask_txt = ", com mascara alfa" if mask is not None else ""
        print(f"[template] {os.path.basename(path)} carregado ({gray.shape[1]}x{gray.shape[0]}px{mask_txt})")

    return templates


def best_match(frame_gray, templates):
    best = None
    for tpl in templates:
        h, w = tpl["gray"].shape[:2]
        if h > frame_gray.shape[0] or w > frame_gray.shape[1]:
            continue
        result = cv2.matchTemplate(frame_gray, tpl["gray"], tpl["method"], mask=tpl["mask"])
        result = np.nan_to_num(result, nan=-1.0, posinf=-1.0, neginf=-1.0)
        _, max_val, _, max_loc = cv2.minMaxLoc(result)
        if best is None or max_val > best["score"]:
            best = {"score": max_val, "loc": max_loc, "size": (w, h), "name": tpl["name"]}
    return best


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
    templates = load_templates(TEMPLATE_DIR, scale=DOWNSCALE)

    hwnd = find_window(WINDOW_TITLE)
    if hwnd is None:
        print(f"[erro] nenhuma janela encontrada com titulo contendo '{WINDOW_TITLE}'.")
        print("Ajuste WINDOW_TITLE no topo do script para um trecho do titulo real da janela.")
        sys.exit(1)
    print(f"[ok] janela encontrada: '{win32gui.GetWindowText(hwnd)}' (hwnd={hwnd})")

    armed = False
    toggle_state = {"was_pressed": False}
    sct = mss.mss()

    print("Pressione F8 para ligar a varredura (e de novo para pausar). Ctrl+C encerra.")

    frame_count = 0
    last_fps_print = time.time()

    try:
        while True:
            if key_just_pressed(TOGGLE_KEY, toggle_state):
                armed = not armed
                print(f"[status] varredura {'LIGADA' if armed else 'PAUSADA'}")

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
            frame_gray_full = cv2.cvtColor(shot[:search_h], cv2.COLOR_BGRA2GRAY)
            if DOWNSCALE != 1.0:
                small_w = max(1, round(frame_gray_full.shape[1] * DOWNSCALE))
                small_h = max(1, round(frame_gray_full.shape[0] * DOWNSCALE))
                frame_gray = cv2.resize(frame_gray_full, (small_w, small_h), interpolation=cv2.INTER_AREA)
            else:
                frame_gray = frame_gray_full

            match = best_match(frame_gray, templates)
            frame_count += 1

            if DEBUG_SHOW:
                preview = cv2.cvtColor(frame_gray, cv2.COLOR_GRAY2BGR)
                if match:
                    x, y = match["loc"]
                    w, h = match["size"]
                    cv2.rectangle(preview, (x, y), (x + w, y + h), (0, 255, 0), 2)
                    cv2.putText(preview, f"{match['score']:.2f}", (x, max(y - 5, 0)),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
                cv2.imshow("debug", preview)
                if cv2.waitKey(1) & 0xFF == 27:
                    break

            now = time.time()
            if now - last_fps_print >= 2:
                fps = frame_count / (now - last_fps_print)
                score_txt = f"{match['score']:.2f}" if match else "-"
                print(f"[debug] ~{fps:.1f} fps | melhor score atual: {score_txt}")
                frame_count = 0
                last_fps_print = now

            if match and match["score"] >= MATCH_THRESHOLD:
                inv = 1.0 / DOWNSCALE
                x, y = match["loc"]
                w, h = match["size"]
                orig_x, orig_y = round(x * inv), round(y * inv)
                orig_w, orig_h = round(w * inv), round(h * inv)
                center_x = region["left"] + orig_x + orig_w // 2
                center_y = region["top"] + orig_y + orig_h // 2

                crop = shot[orig_y:orig_y + orig_h, orig_x:orig_x + orig_w]
                if crop.size > 0:
                    cv2.imwrite(MATCH_DEBUG_FILE, crop)

                print(f"[match] '{match['name']}' score={match['score']:.3f} em ({center_x}, {center_y}) "
                      f"| recorte salvo em {MATCH_DEBUG_FILE}")
                double_click_at(center_x, center_y)
                time.sleep(0.5)
                press_enter()
                print("[ok] duplo clique + Enter realizados. Encerrando.")
                break
    except KeyboardInterrupt:
        print("\n[fim] interrompido pelo usuario.")
    finally:
        if DEBUG_SHOW:
            cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
