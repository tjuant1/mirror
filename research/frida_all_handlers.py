"""
Gancha TODOS os 168 handlers de pacote conhecidos (marcados com opcode
via o atributo NLHNKBGJHFK) de uma vez, direto nas funcoes que
realmente processam o payload decifrado -- assim nao dependemos de
rastrear a pilha assincrona do recebimento, so esperamos ver qual
deles dispara com dados reais.

Uso: python frida_all_handlers.py <PID> <segundos>
"""
import sys
import time
import json
import frida

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 30

with open("opcode_handlers.json") as f:
    HANDLERS = [h for h in json.load(f) if h["has_bytes"]]

print(f"[*] {len(HANDLERS)} handlers to hook", flush=True)

JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var gameBase = gameMod.base;

var handlers = %s;

function dumpIl2CppByteArray(ptr, maxLen) {
    try {
        if (ptr.isNull()) return null;
        var len = ptr.add(0x18).readS32();
        if (len <= 0 || len > 8192) return null;
        var n = Math.min(len, maxLen);
        return { len: len, data: ptr.add(0x20).readByteArray(n) };
    } catch (e) {
        return null;
    }
}

handlers.forEach(function (h) {
    var addr = gameBase.add(parseInt(h.rva, 16));
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var d = dumpIl2CppByteArray(args[0], 300);
                if (d !== null) {
                    send({ opcode: h.opcode, cls: h.cls, method: h.method, len: d.len }, d.data);
                } else {
                    send({ opcode: h.opcode, cls: h.cls, method: h.method, len: -1 });
                }
            }
        });
    } catch (e) {
        send("FAILED " + h.cls + "." + h.method + ": " + e);
    }
});
send("all hooks installed");
""" % json.dumps(HANDLERS)

fire_counts = {}


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    payload = message["payload"]
    if isinstance(payload, str):
        if not payload.startswith("FAILED"):
            print("[info]", payload, flush=True)
        return
    key = f"{payload['cls']}.{payload['method']} ({payload['opcode']})"
    fire_counts[key] = fire_counts.get(key, 0) + 1
    hexstr = data.hex() if data else "(no data)"
    if fire_counts[key] <= 3:
        print(f"[{key}] len={payload['len']} data={hexstr[:200]}", flush=True)


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] watching {DURATION}s -- play normally now...", flush=True)
time.sleep(DURATION)
session.detach()

print(f"\n[*] SUMMARY -- {len(fire_counts)} distinct handlers fired:", flush=True)
for key, count in sorted(fire_counts.items(), key=lambda kv: -kv[1]):
    print(f"  {key}: {count}", flush=True)
