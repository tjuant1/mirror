"""
Verificacao pre-voo: confirma que as 3 contas estao rodando, com a
resolucao certa, e que o gancho Frida + as chamadas internas (mover,
projecao de camera) funcionam -- tudo de um jeito seguro/sem efeito
visivel (moveTo com distancia enorme = sempre "ja esta perto o
suficiente", sem mover de verdade; projecao e so calculo, sem clique).

Uso: python verify_setup.py
"""
import sys
import time

import frida
import win32gui
import win32process

ACCOUNTS = ["InfowP", "Top1z27z11", "SentelhaEl"]
EXPECTED_WIDTH = 1278
EXPECTED_HEIGHT = 665

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
var awakeCount = 0;
Interceptor.attach(awakeAddr, {
    onEnter: function (args) { awakeCount++; }
});

rpc.exports = {
    getAwakeCount: function () { return awakeCount; },
    getLocalBodyPtr: function () {
        var b = getLocalBody();
        return b.isNull() ? null : b.toString();
    },
    testMoveNoop: function () {
        // distancia enorme = a funcao ve que "ja esta perto o suficiente"
        // e retorna sucesso na hora, sem enfileirar nenhum movimento real.
        var image = findImage();
        if (image === null) return { error: "no image" };
        var nsBuf = Memory.allocUtf8String("");
        var nameBuf = Memory.allocUtf8String("Coord");
        var coordClass = il2cpp_class_from_name(image, nsBuf, nameBuf);
        if (coordClass.isNull()) return { error: "Coord class not found" };
        var coordObj = il2cpp_object_new(coordClass);
        coordCtor(coordObj, 0, 0);
        var localBody = getLocalBody();
        if (localBody.isNull()) return { error: "localBody is null" };
        var res = moveToFn(localBody, coordObj, 999999.0, ptr(0), 0, 0);
        return { result: res };
    },
    testProjection: function () {
        var camera = getMain();
        if (camera.isNull()) return { error: "camera.main is null" };
        var posBuf = Memory.alloc(12);
        posBuf.writeFloat(0); posBuf.add(4).writeFloat(0); posBuf.add(8).writeFloat(0);
        var retBuf = Memory.alloc(12);
        w2sInjected(camera, posBuf, 2, retBuf);
        var screenW = getScreenWidth(), screenH = getScreenHeight();
        return { ok: true, unityScreen: [screenW, screenH] };
    }
};
send({ event: "ready" });
"""


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


all_ok = True

for name in ACCOUNTS:
    print(f"\n=== {name} ===", flush=True)
    hwnd = find_window(name)
    if hwnd is None:
        print(f"  [FALHA] janela nao encontrada", flush=True)
        all_ok = False
        continue

    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    region = get_window_region(hwnd)
    print(f"  janela ok (pid={pid}), resolucao={region['width']}x{region['height']}", flush=True)
    if region["width"] != EXPECTED_WIDTH or region["height"] != EXPECTED_HEIGHT:
        print(f"  [AVISO] esperado {EXPECTED_WIDTH}x{EXPECTED_HEIGHT}", flush=True)
        all_ok = False
    else:
        print(f"  resolucao OK", flush=True)

    try:
        session = frida.attach(pid)
        script = session.create_script(JS)
        messages = []
        script.on("message", lambda m, d: messages.append(m))
        script.load()
        time.sleep(0.3)

        body_ptr = script.exports_sync.get_local_body_ptr()
        if body_ptr:
            print(f"  LocalCharacterBody OK ({body_ptr})", flush=True)
        else:
            print(f"  [FALHA] LocalCharacterBody nulo (personagem fora do mundo?)", flush=True)
            all_ok = False

        move_result = script.exports_sync.test_move_noop()
        if "error" in move_result:
            print(f"  [FALHA] moveTo: {move_result['error']}", flush=True)
            all_ok = False
        else:
            print(f"  moveTo (teste sem efeito) OK: {move_result}", flush=True)

        proj_result = script.exports_sync.test_projection()
        if "error" in proj_result:
            print(f"  [FALHA] projecao de camera: {proj_result['error']}", flush=True)
            all_ok = False
        else:
            print(f"  Camera.WorldToScreenPoint OK, tela unity={proj_result['unityScreen']}", flush=True)

        awake_count = script.exports_sync.get_awake_count()
        print(f"  Body.Awake ja disparou {awake_count}x desde o attach (normal, mapa tem NPCs/players)", flush=True)

        session.detach()
        print(f"  [OK] tudo funcionando em {name}", flush=True)
    except Exception as e:
        print(f"  [FALHA] erro ao testar Frida: {e}", flush=True)
        all_ok = False

print("\n" + "=" * 50, flush=True)
if all_ok:
    print("TUDO OK nas 3 contas. Pronto pra rodar rugard_production.py", flush=True)
else:
    print("Alguma coisa precisa de atencao -- ver avisos/falhas acima.", flush=True)
