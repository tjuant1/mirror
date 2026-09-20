"""
Versao com interface grafica do script de producao do Rugard.

Fluxo:
  1. Tela simples pedindo os nicks das contas (separados por virgula).
  2. Tela de log ao vivo com botao "Pausar" (para a automacao, mas deixa
     a janela aberta pra revisar o log) e "Fechar" (encerra tudo).

A logica central (deteccao via Body.Awake, movimento via
LocalCharacterBody.KODIBLNBDKN, clique via Camera.WorldToScreenPoint,
confirmacao via template matching) e identica ao rugard_production.py
ja validado em producao -- so foi encaixada numa interface grafica e
num design que aceita parar de forma limpa a qualquer momento.
"""
import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, font as tkfont

import cv2
import numpy as np
import mss
import frida
import win32api
import win32con
import win32gui
import win32process

# --- caminho base: funciona tanto rodando como script quanto como .exe
# empacotado (o .exe espera a pasta ui_templates/ ao lado dele) ---
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXPECTED_WIDTH = 1278
EXPECTED_HEIGHT = 665
INDEX_MAX = 10000  # NPCs/monstros ficam abaixo disso, jogadores ficam bem acima (18000+)
NPC_NAME_FILTER = "Rugard"

MOVE_DISTANCE = 2.0
REAL_DY_CYCLE = [0.8, 0.4, 1.2, 0.1, 1.6]  # somado ao Y real (pes) do Body
SYNTH_Y_CYCLE = [1.7, 1.2, 0.8, 2.2]  # Y absoluto quando so temos o tile
CLICK_RETRY_INTERVAL = 0.3
CLICK_RETRY_TIMEOUT = 90.0  # generoso pra contas longe; sai na hora se confirmar antes

CONFIRM_TEMPLATE_PATH = os.path.join(BASE_DIR, "ui_templates", "confirmation.png")
CONFIRM_MATCH_THRESHOLD = 0.55
CONFIRM_TIMEOUT = 1.0

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

var rugardBody = null;
function readBodyPos() {
    if (rugardBody === null) return null;
    try {
        var p = rugardBody.add(0x120);
        return [p.readFloat(), p.add(4).readFloat(), p.add(8).readFloat()];
    } catch (e) {
        return null;
    }
}

var awakeAddr = gameBase.add(""" + hex(AWAKE_RVA) + r""");

Interceptor.attach(awakeAddr, {
    onEnter: function (args) {
        var bodyPtr = args[0];
        var attempts = 0;
        var maxAttempts = 34;  // 34 x 30ms ~ 1s de teto, mas normalmente resolve bem antes
        var poll = function () {
            attempts++;
            try {
                var index = bodyPtr.add(0x20).readS32();
                if (index >= """ + str(INDEX_MAX) + r""") return;
                var namePtr = bodyPtr.add(0x28).readPointer();
                var name = readIl2CppString(namePtr);
                if (name === null) {
                    if (attempts < maxAttempts) setTimeout(poll, 30);
                    return;
                }
                if (name.indexOf(""" + json.dumps(NPC_NAME_FILTER) + r""") >= 0) {
                    var coordPtr = bodyPtr.add(0x70).readPointer();
                    var cx = coordPtr.isNull() ? null : coordPtr.add(0x10).readS32();
                    var cy = coordPtr.isNull() ? null : coordPtr.add(0x14).readS32();
                    rugardBody = bodyPtr;
                    send({ event: "found", index: index, name: name, cx: cx, cy: cy, pos: readBodyPos() });
                }
            } catch (e) {
                if (attempts < maxAttempts) setTimeout(poll, 30);
            }
        };
        setTimeout(poll, 30);
    }
});

var coordClassCache = null;
function getCoordClass() {
    if (coordClassCache === null || coordClassCache.isNull()) {
        var image = findImage();
        var nsBuf = Memory.allocUtf8String("");
        var nameBuf = Memory.allocUtf8String("Coord");
        coordClassCache = il2cpp_class_from_name(image, nsBuf, nameBuf);
    }
    return coordClassCache;
}

rpc.exports = {
    prewarm: function () {
        var c = getCoordClass();
        return { ok: !c.isNull() };
    },
    moveTo: function (x, y, distance) {
        var coordClass = getCoordClass();
        if (coordClass.isNull()) return { error: "Coord class not found" };
        var coordObj = il2cpp_object_new(coordClass);
        coordCtor(coordObj, x, y);
        var localBody = getLocalBody();
        if (localBody.isNull()) return { error: "localBody is null" };
        var res = moveToFn(localBody, coordObj, distance, ptr(0), 0, 0);
        return { result: res };
    },
    getRugardPos: function () {
        return readBodyPos();
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

# so uma conta usa o mouse fisico por vez -- evita que 2 contas clicando
# quase ao mesmo tempo "roubem" o cursor uma da outra no meio do clique
click_lock = threading.Lock()


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


def resize_client_area(hwnd, width, height):
    try:
        cl, ct, cr, cb = win32gui.GetClientRect(hwnd)
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        new_w = (right - left) + (width - (cr - cl))
        new_h = (bottom - top) + (height - (cb - ct))
        win32gui.SetWindowPos(hwnd, None, left, top, new_w, new_h,
                              win32con.SWP_NOZORDER | win32con.SWP_NOACTIVATE)
    except Exception:
        pass


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


def focus_window(hwnd):
    """Traz a janela da conta pra frente antes de mandar teclado/mouse.
    keybd_event e um evento GLOBAL do Windows -- ele vai pra janela que
    estiver com foco no sistema no instante do envio, entao se outra conta
    clicar na janela dela nesse meio tempo, o foco muda e o Enter vai
    parar na janela errada. Best-effort: SetForegroundWindow pode falhar
    silenciosamente por restricoes do Windows, mas o clique fisico logo
    antes (mouse_event) normalmente já concede o foco de qualquer forma."""
    try:
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
    except Exception:
        pass


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


class AccountWorker(threading.Thread):
    """Uma thread por conta. Reporta tudo via log_fn (thread-safe) em vez
    de print(), e para de forma limpa assim que stop_event for setado."""

    def __init__(self, name, confirm_template, shared_state, log_fn, stop_event):
        super().__init__(daemon=True)
        self.name = name
        self.confirm_template = confirm_template
        self.shared = shared_state
        self.log = lambda msg: log_fn(self.name, msg)
        self.stop_event = stop_event
        self.session = None
        self.script = None
        # True assim que o PROPRIO Body.Awake desta conta disparar pro
        # Rugard -- ou seja, o npc realmente renderizou no cliente dela
        # (independente de quem foi a conta que avisou a posicao primeiro)
        self.locally_visible = False

    def attach(self):
        self.hwnd = find_window(self.name)
        if self.hwnd is None:
            raise RuntimeError(f"janela '{self.name}' nao encontrada")
        _, self.pid = win32process.GetWindowThreadProcessId(self.hwnd)
        self.sct = mss.mss()
        self.session = frida.attach(self.pid)
        self.script = self.session.create_script(JS)
        self.script.on("message", self.on_message)
        self.script.load()
        try:
            self.script.exports_sync.prewarm()
        except Exception as e:
            self.log(f"prewarm falhou (ok, sera feito no primeiro uso): {e}")
        region = get_window_region(self.hwnd)
        if region["width"] != EXPECTED_WIDTH or region["height"] != EXPECTED_HEIGHT:
            self.log(f"janela em {region['width']}x{region['height']}, ajustando para {EXPECTED_WIDTH}x{EXPECTED_HEIGHT}...")
            resize_client_area(self.hwnd, EXPECTED_WIDTH, EXPECTED_HEIGHT)
            time.sleep(0.2)
            region = get_window_region(self.hwnd)
            if region["width"] != EXPECTED_WIDTH or region["height"] != EXPECTED_HEIGHT:
                self.log(
                    f"!!! AVISO: nao consegui ajustar (agora {region['width']}x{region['height']}) "
                    f"-- a deteccao do dialogo de confirmacao pode falhar nesta conta."
                )
            else:
                self.log("janela ajustada.")
        self.log(f"anexado (pid={self.pid})")

    def tlog(self, stage):
        t0 = self.shared.get("t_detect")
        if t0 is not None:
            self.log(f"[t+{(time.perf_counter() - t0) * 1000:.0f}ms] {stage}")

    def on_message(self, message, data):
        if message["type"] != "send":
            self.log(f"[error] {message}")
            return
        payload = message["payload"]
        if payload.get("event") == "found" and payload.get("cx") is not None:
            if not self.locally_visible:
                self.locally_visible = True
                self.log(f"Rugard renderizado nesta conta. tile=({payload['cx']},{payload['cy']}) pos_real={payload.get('pos')}")
            with self.shared["lock"]:
                if not self.shared["set"]:
                    self.shared["set"] = True
                    self.shared["cx"] = payload["cx"]
                    self.shared["cy"] = payload["cy"]
                    self.shared["t_detect"] = time.perf_counter()
                    self.shared["event"].set()
                    self.log(f"*** RUGARD DETECTADO em ({payload['cx']},{payload['cy']}) *** avisando as outras contas")

    def run(self):
        try:
            self.attach()
        except Exception as e:
            self.log(f"!!! FALHA ao anexar: {e}")
            return

        while not self.shared["event"].wait(0.2) and not self.stop_event.is_set():
            pass

        if self.stop_event.is_set() and not self.shared["set"]:
            self.log("pausado antes de detectar o Rugard.")
            self._safe_detach()
            return

        cx, cy = self.shared["cx"], self.shared["cy"]
        self.tlog("iniciando movimento")
        self.log(f"movendo para ({cx},{cy})...")
        move_result = self.script.exports_sync.move_to(cx, cy, MOVE_DISTANCE)
        self.tlog("movimento disparado")
        self.log(f"resultado do movimento: {move_result}")

        world_x, world_z = cx + 0.5, cy + 0.5
        deadline = time.time() + CLICK_RETRY_TIMEOUT

        # so vale a pena tentar clicar quando o Rugard JA renderizou no
        # cliente desta conta (proprio Body.Awake). Antes disso, a projecao
        # da camera pode dizer "na tela" so pela matematica da posicao do
        # mundo, mesmo com o npc ainda nao carregado -- clicar nesse
        # momento so gera tentativas inuteis que prendem o click_lock e
        # atrasam contas que ja estao prontas de verdade. Enquanto isso,
        # so fica monitorando (sem tocar no lock) ate o proprio Awake
        # confirmar, exatamente como as outras contas fazem em paralelo.
        if not self.locally_visible:
            self.log("Rugard ainda nao renderizou aqui -- aguardando (personagem a caminho)...")
            while not self.locally_visible and time.time() < deadline and not self.stop_event.is_set():
                time.sleep(0.03)

        clicked = False
        attempt = 0
        while self.locally_visible and time.time() < deadline and not clicked and not self.stop_event.is_set():
            # posicao REAL do npc neste cliente (Body.Position); so cai na
            # estimativa por tile se nao houver leitura valida. A altura do
            # clique varia a cada tentativa que falha, pra corrigir sozinho
            # se o primeiro ponto cair acima/abaixo do modelo (npc sentado).
            real = self.script.exports_sync.get_rugard_pos()
            if real and (abs(real[0]) > 0.001 or abs(real[2]) > 0.001):
                px, pz = real[0], real[2]
                py = real[1] + REAL_DY_CYCLE[attempt % len(REAL_DY_CYCLE)]
            else:
                px, pz = world_x, world_z
                py = SYNTH_Y_CYCLE[attempt % len(SYNTH_Y_CYCLE)]
            attempt += 1
            proj = self.script.exports_sync.get_screen_point_for_world(px, py, pz)
            if "error" not in proj:
                sx, sy, sz = proj["screenPos"]
                screen_w, screen_h = proj["unityScreen"]
                if sz >= 0 and 0 <= sx <= screen_w and 0 <= sy <= screen_h:
                    region = get_window_region(self.hwnd)
                    scale_x = region["width"] / screen_w
                    scale_y = region["height"] / screen_h
                    win_x = region["left"] + int(round(sx * scale_x))
                    win_y = region["top"] + int(round((screen_h - sy) * scale_y))
                    self.log(f"clicando em ({win_x},{win_y})... (tentativa {attempt}, y={py:.2f})")
                    # clique + confirmacao + enter formam uma secao critica:
                    # se outra conta clicar na janela dela no meio desse
                    # intervalo, ela rouba o foco global do Windows e o
                    # Enter desta conta vai parar na janela errada (bug
                    # visto em producao: 2 contas confirmando quase juntas,
                    # so uma delas de fato entrou no evento).
                    with click_lock:
                        self.tlog("lock obtido, clicando")
                        focus_window(self.hwnd)
                        double_click_at(win_x, win_y)
                        self.tlog("clique feito")
                        if self._wait_for_confirmation(region):
                            self.tlog("dialogo visto")
                            focus_window(self.hwnd)
                            press_enter()
                            self.tlog("Enter enviado")
                            self.log("*** CONFIRMADO, Enter enviado ***")
                            clicked = True
                        else:
                            self.log("clique nao confirmado, tentando de novo...")
                else:
                    self.log("ainda fora da tela, tentando de novo...")
            else:
                self.log(f"erro na projecao: {proj['error']}")
            if not clicked and not self.stop_event.is_set():
                time.sleep(CLICK_RETRY_INTERVAL)

        if self.stop_event.is_set() and not clicked:
            self.log("pausado pelo usuario.")
        elif not clicked and not self.locally_visible:
            self.log("!!! Rugard nunca renderizou nesta conta dentro do tempo limite (distancia grande demais?)")
        elif not clicked:
            self.log("!!! nao conseguiu confirmar dentro do tempo limite")

        self._safe_detach()

    def _wait_for_confirmation(self, region, timeout=CONFIRM_TIMEOUT):
        deadline = time.time() + timeout
        best_score = -1.0
        while time.time() < deadline:
            score, _ = confirmation_score(self.sct, region, self.confirm_template)
            best_score = max(best_score, score)
            if score >= CONFIRM_MATCH_THRESHOLD:
                self.log(f"[confirm] dialogo detectado (score={score:.3f})")
                return True
            time.sleep(0.05)
        self.log(f"[confirm] dialogo NAO detectado (melhor score={best_score:.3f})")
        return False

    def _safe_detach(self):
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Rugard Auto-Click")
        self.root.configure(bg="#1e1e1e")
        self.stop_event = threading.Event()
        self.workers = []
        self.log_queue = queue.Queue()
        self.confirm_template = None
        self.build_input_screen()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # --- tela 1: pedir os nicks ---
    def build_input_screen(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.geometry("520x220")
        mono = tkfont.Font(family="Consolas", size=11)

        frame = tk.Frame(self.root, bg="#1e1e1e", padx=20, pady=20)
        frame.pack(fill="both", expand=True)

        label = tk.Label(
            frame,
            text="Digite os nicks das contas logadas, separados por virgula:\n(ex: SentelhaEl, InfowP, Top1z27z11)",
            bg="#1e1e1e", fg="#e0e0e0", font=mono, justify="left",
        )
        label.pack(anchor="w", pady=(0, 10))

        self.entry = tk.Entry(frame, font=mono, bg="#2d2d2d", fg="#e0e0e0", insertbackground="#e0e0e0")
        self.entry.pack(fill="x", pady=(0, 15))
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self.on_submit())

        btn = tk.Button(frame, text="Iniciar (Enter)", command=self.on_submit, bg="#3a3a3a", fg="#e0e0e0")
        btn.pack(anchor="e")

        self.error_label = tk.Label(frame, text="", bg="#1e1e1e", fg="#ff6b6b", font=mono)
        self.error_label.pack(anchor="w", pady=(10, 0))

    def on_submit(self):
        text = self.entry.get().strip()
        accounts = [a.strip() for a in text.split(",") if a.strip()]
        if not accounts:
            self.error_label.config(text="Digite pelo menos um nick.")
            return
        self.build_log_screen(accounts)
        self.start_workers(accounts)

    # --- tela 2: log ao vivo ---
    def build_log_screen(self, accounts):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.geometry("900x520")
        mono = tkfont.Font(family="Consolas", size=10)

        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(fill="x", padx=10, pady=(10, 0))
        tk.Label(
            top, text=f"Monitorando: {', '.join(accounts)}", bg="#1e1e1e", fg="#e0e0e0", font=mono,
        ).pack(side="left")

        self.text = scrolledtext.ScrolledText(
            self.root, bg="#0f0f0f", fg="#c0f0c0", font=mono, wrap="word", state="disabled",
        )
        self.text.pack(fill="both", expand=True, padx=10, pady=10)

        btns = tk.Frame(self.root, bg="#1e1e1e")
        btns.pack(fill="x", padx=10, pady=(0, 10))
        self.pause_btn = tk.Button(btns, text="Pausar", command=self.on_pause, bg="#5a4a1a", fg="#ffe0a0", width=15)
        self.pause_btn.pack(side="left")
        tk.Button(btns, text="Fechar", command=self.on_close, bg="#5a1a1a", fg="#ffb0b0", width=15).pack(side="left", padx=(10, 0))

        self.root.after(100, self.poll_log_queue)

    def append_log(self, name, msg):
        self.log_queue.put(f"[{time.strftime('%H:%M:%S')}] [{name}] {msg}")

    def poll_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.text.configure(state="normal")
                self.text.insert(tk.END, line + "\n")
                self.text.see(tk.END)
                self.text.configure(state="disabled")
        except queue.Empty:
            pass
        if not self.stop_event.is_set() or any(w.is_alive() for w in self.workers):
            self.root.after(100, self.poll_log_queue)

    def start_workers(self, accounts):
        try:
            self.confirm_template = load_confirm_template(CONFIRM_TEMPLATE_PATH)
        except Exception as e:
            self.append_log("*", f"!!! ERRO ao carregar template de confirmacao: {e}")
            return

        shared = {"lock": threading.Lock(), "event": threading.Event(), "cx": None, "cy": None, "set": False, "t_detect": None}
        self.append_log("*", "todas as contas conectando, monitorando o spawn do Rugard...")
        for name in accounts:
            worker = AccountWorker(name, self.confirm_template, shared, self.append_log, self.stop_event)
            worker.start()
            self.workers.append(worker)

    def on_pause(self):
        self.stop_event.set()
        self.append_log("*", "PAUSADO -- nenhuma nova acao sera tomada. Feche a janela quando quiser encerrar.")
        self.pause_btn.config(state="disabled")

    def on_close(self):
        self.stop_event.set()
        self.root.after(300, self.root.destroy)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
