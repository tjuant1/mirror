"""
Gancha Body.Awake() (metodo de inicializacao do Unity, chamado quando
qualquer GameObject com o componente Body e criado/ativado) -- isso
deve disparar pra QUALQUER entidade nova (monstro, NPC, jogador),
independente de qual pacote de rede foi usado pra anuncia-la. Le
Name, Index e TargetCoordinates direto da memoria do objeto.

Filtro por Index: observado empiricamente que jogadores tem Index alto
(18000+, provavelmente uma faixa reservada pra slots de personagem),
enquanto NPCs/monstros usam Index baixo (visto: 0-84 na area do
Elbeland). Por padrao so mostra Index < INDEX_MAX (jogadores ficam de
fora), reduzindo bastante o ruido quando tem muitos players no mapa.

Uso: python frida_body_awake.py <PID> <segundos> [index_max]
"""
import sys
import time
import frida

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 30
INDEX_MAX = int(sys.argv[3]) if len(sys.argv) > 3 else 10000
RVA = 0xD2DF30  # Body.Awake

JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var addr = gameMod.base.add(""" + hex(RVA) + r""");

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

var INDEX_MAX = """ + str(INDEX_MAX) + r""";

function readBodyLater(bodyPtr) {
    try {
        var index = bodyPtr.add(0x20).readS32();
        if (index >= INDEX_MAX) return;  // provavelmente um jogador, ignora
        var namePtr = bodyPtr.add(0x28).readPointer();
        var name = readIl2CppString(namePtr);
        var coordPtr = bodyPtr.add(0x70).readPointer();
        var cx = null, cy = null;
        if (!coordPtr.isNull()) {
            cx = coordPtr.add(0x10).readS32();
            cy = coordPtr.add(0x14).readS32();
        }
        send({ index: index, name: name, cx: cx, cy: cy });
    } catch (e) {
        send({ error: e.toString() });
    }
}

Interceptor.attach(addr, {
    onEnter: function (args) {
        var bodyPtr = args[0];
        setTimeout(function () { readBodyLater(bodyPtr); }, 1000);
    }
});
send("hooked Body.Awake");
"""


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    payload = message["payload"]
    if isinstance(payload, str):
        print("[info]", payload, flush=True)
        return
    print(f"[spawn] {payload}", flush=True)


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] watching {DURATION}s -- walk around so new monsters/NPCs come into view...", flush=True)
time.sleep(DURATION)
time.sleep(1.5)  # deixa os setTimeout pendentes terminarem
session.detach()
print("[*] done.", flush=True)
