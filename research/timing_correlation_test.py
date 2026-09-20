"""
Teste de correlacao de tempo: gancha Body.Awake (nosso metodo atual de
deteccao) E todos os 212 opcodes catalogados ao mesmo tempo, so
registrando o INSTANTE em que cada coisa dispara (sem tentar decodificar
o conteudo). A ideia: se algum opcode disparar visivelmente ANTES do
Body.Awake pra uma entidade nova, e sinal de que o servidor avisa sobre
o objeto antes dele renderizar -- aí vale a pena decodificar aquele
opcode especifico pra detectar o spawn mais cedo. Se nada disparar
antes, confirma que Body.Awake ja e o ponto mais cedo possivel.

Uso: python timing_correlation_test.py <PID> <segundos>
Enquanto roda: ande em direcao a uma area com monstros que voce ainda
nao viu nessa sessao (nao efeito se so tiver monstros ja carregados).
"""
import sys
import time
import json
import frida

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 40

AWAKE_RVA = 0xD2DF30
INDEX_MAX = 10000

with open("opcode_handlers.json") as f:
    ALL_HANDLERS = json.load(f)

JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var gameBase = gameMod.base;

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

var t0 = Date.now();

// --- Body.Awake, igual ao que ja usamos em producao ---
var awakeAddr = gameBase.add(""" + hex(AWAKE_RVA) + r""");
Interceptor.attach(awakeAddr, {
    onEnter: function (args) {
        var bodyPtr = args[0];
        var attempts = 0;
        var poll = function () {
            attempts++;
            try {
                var index = bodyPtr.add(0x20).readS32();
                if (index >= """ + str(INDEX_MAX) + r""") return;
                var namePtr = bodyPtr.add(0x28).readPointer();
                var name = readIl2CppString(namePtr);
                if (name === null) {
                    if (attempts < 10) setTimeout(poll, 100);
                    return;
                }
                send({ kind: "awake", t: Date.now() - t0, name: name, index: index });
            } catch (e) {
                if (attempts < 10) setTimeout(poll, 100);
            }
        };
        setTimeout(poll, 150);
    }
});

// --- todos os 212 opcodes, so timestamp + opcode, sem decodificar conteudo ---
var handlers = """ + json.dumps(ALL_HANDLERS) + r""";
handlers.forEach(function (h) {
    var addr = gameBase.add(parseInt(h.rva, 16));
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                send({ kind: "opcode", t: Date.now() - t0, opcode: h.opcode, cls: h.cls, method: h.method });
            }
        });
    } catch (e) {}
});
send({ kind: "ready" });
"""

events = []


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    payload = message["payload"]
    if payload.get("kind") == "ready":
        print("[info] hooks instalados (Body.Awake + 212 opcodes)", flush=True)
        return
    events.append(payload)
    if payload["kind"] == "awake":
        print(f"t={payload['t']:6d}ms  [AWAKE] {payload['name']} (index={payload['index']})", flush=True)


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] gravando por {DURATION}s -- ande em direcao a monstros novos agora...", flush=True)
time.sleep(DURATION)
session.detach()

with open("timing_events.json", "w") as f:
    json.dump(events, f, indent=1)
print(f"\n[*] {len(events)} eventos salvos em timing_events.json", flush=True)
