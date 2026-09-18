"""
Gancha soh Unit.MMONANLPHHC (C1:D7) e salva TODAS as amostras (com
timestamp) num arquivo, pra analisar tendencia por entidade depois,
em vez de so ver as 3 primeiras linhas na tela.

Uso: python frida_log_unit.py <PID> <segundos>
"""
import sys
import time
import frida

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 30
RVA = 0x12BF7C0  # Unit.MMONANLPHHC

JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var addr = gameMod.base.add(""" + hex(RVA) + r""");

function dumpIl2CppByteArray(ptr, maxLen) {
    try {
        if (ptr.isNull()) return null;
        var len = ptr.add(0x18).readS32();
        if (len <= 0 || len > 8192) return null;
        var n = Math.min(len, maxLen);
        return ptr.add(0x20).readByteArray(n);
    } catch (e) {
        return null;
    }
}

Interceptor.attach(addr, {
    onEnter: function (args) {
        var d = dumpIl2CppByteArray(args[0], 64);
        if (d !== null) {
            send({ t: Date.now() }, d);
        }
    }
});
send("hooked");
"""

rows = []


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    payload = message["payload"]
    if isinstance(payload, str):
        print("[info]", payload, flush=True)
        return
    if data:
        rows.append((payload["t"], data.hex()))


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] watching {DURATION}s -- walk in a straight line now...", flush=True)
time.sleep(DURATION)
session.detach()

with open("unit_log.txt", "w") as f:
    for t, hexstr in rows:
        f.write(f"{t}\t{hexstr}\n")
print(f"[*] {len(rows)} samples saved to unit_log.txt", flush=True)
