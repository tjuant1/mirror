"""
Gancha recvfrom/send no ws2_32.dll (que sabemos que disparam de
verdade) e captura o STACK TRACE no momento da chamada. Resolve cada
endereco do stack contra a tabela de 218 mil metodos do Il2CppDumper
pra mostrar exatamente qual cadeia de funcoes do jogo (GameAssembly.dll)
esta por tras de cada envio/recebimento real.

Uso: python frida_backtrace.py <PID> <segundos>
"""
import sys
import time
import bisect
import pickle
import frida

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 20

with open("addr_lookup.pkl", "rb") as f:
    ADDR_NAME = pickle.load(f)
ADDRS = [a for a, _ in ADDR_NAME]


def resolve(rva):
    i = bisect.bisect_right(ADDRS, rva) - 1
    if i < 0:
        return None
    addr, name = ADDR_NAME[i]
    return f"{name}+0x{rva - addr:x}"


JS = r"""
var mod = Process.getModuleByName("ws2_32.dll");
var gameMod = Process.getModuleByName("GameAssembly.dll");
var gameBase = gameMod.base;
var gameEnd = gameBase.add(gameMod.size);

["recvfrom", "send"].forEach(function (fname) {
    var addr = mod.getExportByName(fname);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.fname = fname;
            this.len = args[2].toInt32();
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            var rvas = [];
            for (var i = 0; i < bt.length; i++) {
                var a = bt[i];
                if (a.compare(gameBase) >= 0 && a.compare(gameEnd) < 0) {
                    rvas.push(a.sub(gameBase).toInt32());
                }
            }
            this.rvas = rvas;
        },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0) {
                send({ f: this.fname, n: n, rvas: this.rvas });
            }
        }
    });
});
send("hooks installed");
"""

seen_chains = {}


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    payload = message["payload"]
    if isinstance(payload, str):
        print("[info]", payload, flush=True)
        return
    resolved = [resolve(rva) for rva in payload["rvas"]]
    key = (payload["f"], tuple(resolved))
    seen_chains[key] = seen_chains.get(key, 0) + 1


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] watching {DURATION}s -- play normally now...", flush=True)
time.sleep(DURATION)
session.detach()

print(f"\n[*] {len(seen_chains)} distinct call chains seen:\n", flush=True)
for (fname, chain), count in sorted(seen_chains.items(), key=lambda kv: -kv[1]):
    print(f"=== {fname} (x{count}) ===", flush=True)
    for frame in chain:
        print("   ", frame, flush=True)
    print(flush=True)
