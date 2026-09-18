"""
Script de producao final: 3 contas cobrindo o mapa do evento.
Qualquer uma que detectar o Rugard (Body.Awake, nome contendo
"Rugard", Index < 10000 = NPC nao jogador) avisa as outras duas.
As 3 entao: andam ate a posicao, clicam nele via projecao de camera
real do Unity (sem visao computacional), esperam o dialogo
"DOPPELGANGER" aparecer na tela e apertam Enter pra confirmar.

Uso:
    python rugard_production.py
Ctrl+C encerra a qualquer momento.
"""
import json
import sys
import time
import threading

import cv2
import numpy as np
import mss
import frida
import win32api
import win32con
import win32gui
import win32process

ACCOUNTS = ["InfowP", "Top1z27z11", "SentelhaEl"]
EXPECTED_WIDTH = 1278
EXPECTED_HEIGHT = 665
INDEX_MAX = 10000  # NPCs/monstros ficam abaixo disso, jogadores ficam bem acima (18000+)
NPC_NAME_FILTER = "Rugard"

MOVE_DISTANCE = 2.0
WORLD_HEIGHT_DEFAULT = 1.7
CLICK_RETRY_INTERVAL = 0.3
CLICK_RETRY_TIMEOUT = 30.0

CONFIRM_TEMPLATE_PATH = "ui_templates/confirmation.png"
CONFIRM_MATCH_THRESHOLD = 0.55
CONFIRM_TIMEOUT = 1.0
CONFIRM_DEBUG_DIR = "confirm_debug"

# so uma conta usa o mouse fisico por vez -- evita que 2 contas clicando
# quase ao mesmo tempo "roubem" o cursor uma da outra no meio do clique
click_lock = threading.Lock()

AWAKE_RVA = 0xD2DF30
GET_LOCAL_BODY_RVA = 0x1233EE0
MOVE_TO_RVA = 0xD661F0
COORD_CTOR_RVA = 0x3B8590
CAMERA_GET_MAIN_RVA = 0x464D920
CAMERA_W2S_INJECTED_RVA = 0x464EB90
SCREEN_GET_WIDTH_RVA = 0x46597C0
SCREEN_GET_HEIGHT_RVA = 0x4659810

JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var gameBase = gameMod.base;

var il2cpp_domain_get = new NativeFunction(gameMod.getExportByName("il2cpp_domain_get"), "pointer", []);
var il2cpp_domain_get_assemblies = new NativeFunction(gameMod.getExportByName("il2cpp_domain_get_assemblies"), "pointer", ["pointer", "pointer"]);
var il2cpp_assembly_get_image = new NativeFunction(gameMod.getExportByName("il2cpp_assembly_get_image"), "pointer", ["pointer"]);
var il2cpp_class_from_name = new NativeFunction(gameMod.getExportByName("il2cpp_class_from_name"), "pointer", ["pointer", "pointer", "pointer"]);
var il2cpp_object_new = new NativeFunction(gameMod.getExportByName("il2cpp_object_new"), "pointer", ["pointer"]);
var il2cpp_image_get_name = new NativeFunction(gameMod.getExportByName("il2cpp_image_get_name"), "pointer", ["pointer"]);

var getLocalBody = new NativeFunction(gameBase.add(""" + hex(GET_LOCAL_BODY_RVA) + r"""), "pointer", []);
var coordCtor = new NativeFunction(gameBase.add(""" + hex(COORD_CTOR_RVA) + r"""), "void", ["pointer", "int", "int"]);
var moveToFn = new NativeFunction(gameBase.add(""" + hex(MOVE_TO_RVA) + r"""), "uint8", ["pointer", "pointer", "float", "pointer", "uint8", "uint8"]);
var getMain = new NativeFunction(gameBase.add(""" + hex(CAMERA_GET_MAIN_RVA) + r"""), "pointer", []);
var w2sInjected = new NativeFunction(gameBase.add(""" + hex(CAMERA_W2S_INJECTED_RVA) + r"""), "void", ["pointer", "pointer", "int", "pointer"]);
var getScreenWidth = new NativeFunction(gameBase.add(""" + hex(SCREEN_GET_WIDTH_RVA) + r"""), "int", []);
var getScreenHeight = new NativeFunction(gameBase.add(""" + hex(SCREEN_GET_HEIGHT_RVA) + r"""), "int", []);

function readIl2CppString(ptr) {
    try {
        if (ptr.isNull()) return null;
        var len = ptr.add(0x10).readS32();
        if (len < 0 || len > 256) return null;
        return ptr.add(0x14).readUtf16String(len);
    } catch (e) {
        return null;
    }
}

function findImage() {
    var domain = il2cpp_domain_get();
    var sizeBuf = Memory.alloc(8);
    var assembliesPtr = il2cpp_domain_get_assemblies(domain, sizeBuf);
    var count = sizeBuf.readU64().toNumber();
    for (var i = 0; i < count; i++) {
        var asm = assembliesPtr.add(i * Process.pointerSize).readPointer();
        var img = il2cpp_assembly_get_image(asm);
        var namePtr = il2cpp_image_get_name(img);
        var name = namePtr.readCString();
        if (name && name.indexOf("Assembly-CSharp") >= 0 && name.indexOf("firstpass") < 0) {
            return img;
        }
    }
    if (count > 0) return il2cpp_assembly_get_image(assembliesPtr.add(0).readPointer());
    return null;
}

var awakeAddr = gameBase.add(""" + hex(AWAKE_RVA) + r""");

Interceptor.attach(awakeAddr, {
    onEnter: function (args) {
        var bodyPtr = args[0];
        var attempts = 0;
        var maxAttempts = 10;  // 10 x 100ms = 1s de teto, mas normalmente resolve bem antes
        var poll = function () {
            attempts++;
            try {
                var index = bodyPtr.add(0x20).readS32();
                if (index >= """ + str(INDEX_MAX) + r""") return;
                var namePtr = bodyPtr.add(0x28).readPointer();
                var name = readIl2CppString(namePtr);
                if (name === null) {
                    if (attempts < maxAttempts) setTimeout(poll, 100);
                    return;
                }
                if (name.indexOf(""" + json.dumps(NPC_NAME_FILTER) + r""") >= 0) {
                    var coordPtr = bodyPtr.add(0x70).readPointer();
                    var cx = coordPtr.isNull() ? null : coordPtr.add(0x10).readS32();
                    var cy = coordPtr.isNull() ? null : coordPtr.add(0x14).readS32();
                    send({ event: "found", index: index, name: name, cx: cx, cy: cy });
                }
            } catch (e) {
                if (attempts < maxAttempts) setTimeout(poll, 100);
            }
        };
        setTimeout(poll, 150);
    }
});

rpc.exports = {
    moveTo: function (x, y, distance) {
        var image = findImage();
        var nsBuf = Memory.allocUtf8String("");
        var nameBuf = Memory.allocUtf8String("Coord");
        var coordClass = il2cpp_class_from_name(image, nsBuf, nameBuf);
        if (coordClass.isNull()) return { error: "Coord class not found" };
        var coordObj = il2cpp_object_new(coordClass);
        coordCtor(coordObj, x, y);
        var localBody = getLocalBody();
        if (localBody.isNull()) return { error: "localBody is null" };
        var res = moveToFn(localBody, coordObj, distance, ptr(0), 0, 0);
        return { result: res };
    },
    getScreenPointForWorld: function (wx, wy, wz) {
        var camera = getMain();
        if (camera.isNull()) return { error: "camera.main is null" };
        var posBuf = Memory.alloc(12);
        posBuf.writeFloat(wx); posBuf.add(4).writeFloat(wy); posBuf.add(8).writeFloat(wz);
        var retBuf = Memory.alloc(12);
        w2sInjected(camera, posBuf, 2, retBuf);
        var sx = retBuf.readFloat(), sy = retBuf.add(4).readFloat(), sz = retBuf.add(8).readFloat();
        var screenW = getScreenWidth(), screenH = getScreenHeight();
        return { screenPos: [sx, sy, sz], unityScreen: [screenW, screenH] };
    }
};
send({ event: "ready" });
"""

# --- estado compartilhado entre as 3 contas ---
shared_lock = threading.Lock()
shared_coord = {"cx": None, "cy": None, "set": False}


def find_window(title_substring):
    title_substring = title_substring.lower()
    found = []

    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title and title_substring in title.lower():
                found.append(hwnd)

    win32gui.EnumWindows(cb, None)
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


def wait_for_confirmation(sct, region, template_gray, name, timeout=CONFIRM_TIMEOUT):
    deadline = time.time() + timeout
    best_score = -1.0
    best_shot = None
    while time.time() < deadline:
        score, shot = confirmation_score(sct, region, template_gray)
        if score > best_score:
            best_score, best_shot = score, shot
        if score >= CONFIRM_MATCH_THRESHOLD:
            print(f"[{name}] [confirm] dialogo detectado (score={score:.3f})", flush=True)
            return True
        time.sleep(0.05)
    if best_shot is not None:
        import os
        os.makedirs(CONFIRM_DEBUG_DIR, exist_ok=True)
        cv2.imwrite(f"{CONFIRM_DEBUG_DIR}/{name}.png", cv2.cvtColor(best_shot, cv2.COLOR_BGRA2BGR))
    print(f"[{name}] [confirm] dialogo NAO detectado (melhor score={best_score:.3f})", flush=True)
    return False


class AccountWorker(threading.Thread):
    def __init__(self, name, confirm_template):
        super().__init__(daemon=True)
        self.name = name
        self.confirm_template = confirm_template
        self.hwnd = find_window(name)
        if self.hwnd is None:
            raise RuntimeError(f"janela '{name}' nao encontrada")
        _, self.pid = win32process.GetWindowThreadProcessId(self.hwnd)
        self.sct = mss.mss()
        self.session = frida.attach(self.pid)
        self.script = self.session.create_script(JS)
        self.script.on("message", self.on_message)
        self.script.load()
        region = get_window_region(self.hwnd)
        if region["width"] != EXPECTED_WIDTH or region["height"] != EXPECTED_HEIGHT:
            print(
                f"[{self.name}] !!! AVISO: janela esta em {region['width']}x{region['height']}, "
                f"esperado {EXPECTED_WIDTH}x{EXPECTED_HEIGHT} -- a deteccao do dialogo de confirmacao "
                f"(template capturado nessa resolucao) pode falhar nesta conta.",
                flush=True,
            )
        print(f"[{self.name}] anexado (pid={self.pid})", flush=True)

    def on_message(self, message, data):
        if message["type"] != "send":
            print(f"[{self.name}] [error] {message}", flush=True)
            return
        payload = message["payload"]
        if payload.get("event") == "found" and payload.get("cx") is not None:
            with shared_lock:
                if not shared_coord["set"]:
                    shared_coord["set"] = True
                    shared_coord["cx"] = payload["cx"]
                    shared_coord["cy"] = payload["cy"]
                    print(f"[{self.name}] *** RUGARD DETECTADO em ({payload['cx']},{payload['cy']}) *** avisando as outras contas", flush=True)

    def run(self):
        # espera qualquer conta (inclusive esta) detectar o Rugard
        while not shared_coord["set"]:
            time.sleep(0.2)

        cx, cy = shared_coord["cx"], shared_coord["cy"]
        print(f"[{self.name}] movendo para ({cx},{cy})...", flush=True)
        move_result = self.script.exports_sync.move_to(cx, cy, MOVE_DISTANCE)
        print(f"[{self.name}] resultado do movimento: {move_result}", flush=True)

        world_x, world_z = cx + 0.5, cy + 0.5
        deadline = time.time() + CLICK_RETRY_TIMEOUT
        clicked = False
        while time.time() < deadline and not clicked:
            proj = self.script.exports_sync.get_screen_point_for_world(world_x, WORLD_HEIGHT_DEFAULT, world_z)
            if "error" not in proj:
                sx, sy, sz = proj["screenPos"]
                screen_w, screen_h = proj["unityScreen"]
                if sz >= 0 and 0 <= sx <= screen_w and 0 <= sy <= screen_h:
                    region = get_window_region(self.hwnd)
                    scale_x = region["width"] / screen_w
                    scale_y = region["height"] / screen_h
                    win_x = region["left"] + int(round(sx * scale_x))
                    win_y = region["top"] + int(round((screen_h - sy) * scale_y))
                    print(f"[{self.name}] clicando em ({win_x},{win_y})...", flush=True)
                    with click_lock:
                        double_click_at(win_x, win_y)
                    time.sleep(0.3)
                    if wait_for_confirmation(self.sct, region, self.confirm_template, self.name):
                        press_enter()
                        print(f"[{self.name}] *** CONFIRMADO, Enter enviado ***", flush=True)
                        clicked = True
                    else:
                        print(f"[{self.name}] clique nao confirmado, tentando de novo...", flush=True)
                else:
                    print(f"[{self.name}] ainda fora da tela, tentando de novo em {CLICK_RETRY_INTERVAL}s...", flush=True)
            else:
                print(f"[{self.name}] erro na projecao: {proj['error']}", flush=True)
            if not clicked:
                time.sleep(CLICK_RETRY_INTERVAL)

        if not clicked:
            print(f"[{self.name}] !!! nao conseguiu confirmar dentro do tempo limite", flush=True)
        self.session.detach()


def main():
    print("[*] carregando template de confirmacao...", flush=True)
    confirm_template = load_confirm_template(CONFIRM_TEMPLATE_PATH)

    workers = [AccountWorker(name, confirm_template) for name in ACCOUNTS]

    print("[*] todas as contas prontas, monitorando o spawn do Rugard...", flush=True)
    for w in workers:
        w.start()

    try:
        for w in workers:
            w.join()
    except KeyboardInterrupt:
        print("\n[fim] interrompido pelo usuario.", flush=True)

    print("[*] concluido.", flush=True)


if __name__ == "__main__":
    main()
