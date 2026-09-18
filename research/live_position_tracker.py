"""
Rastreador de posicao ao vivo: gancha Unit.MMONANLPHHC (opcode C1:D7,
achado e confirmado via engenharia reversa) e mostra uma tabela ao
vivo de todas as entidades proximas com X,Y atuais -- destacando
quais estao PARADAS (uteis pra identificar NPCs sentados, tipo o
Rugard, assim que aparecerem).

Formato do pacote confirmado empiricamente:
  byte0=0xc1 (header)
  byte1=0x08 (tamanho, 8 bytes total)
  byte2=0xd7 (opcode)
  byte3,4 = ID da entidade (2 bytes)
  byte5 = X (direto, sem criptografia extra)
  byte6 = Y (direto, sem criptografia extra)
  byte7 = ? (nao identificado ainda -- talvez direcao/estado)

Uso: python live_position_tracker.py <PID>
Ctrl+C pra parar.
"""
import sys
import time
import frida

PID = int(sys.argv[1])
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
        var d = dumpIl2CppByteArray(args[0], 16);
        if (d !== null) {
            send({}, d);
        }
    }
});
send("hooked");
"""

STALE_AFTER = 15.0  # segundos sem update = considera que saiu de vista

entities = {}  # entity_id -> {"x":..., "y":..., "last_seen":..., "history": [(t,x,y),...]}


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    if not data or len(data) < 7:
        return
    entity_id = data[3] << 8 | data[4]
    x = data[5]
    y = data[6]
    now = time.time()
    e = entities.setdefault(entity_id, {"history": []})
    e["x"] = x
    e["y"] = y
    e["last_seen"] = now
    e["history"].append((now, x, y))
    e["history"] = [h for h in e["history"] if now - h[0] < 10.0]


print(f"[*] attaching to pid {PID}...", flush=True)
session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print("[*] rastreando... Ctrl+C pra parar.\n", flush=True)

try:
    while True:
        time.sleep(2.0)
        now = time.time()
        # limpa entidades velhas
        for eid in list(entities.keys()):
            if now - entities[eid]["last_seen"] > STALE_AFTER:
                del entities[eid]
        if not entities:
            print("(nenhuma entidade visivel ainda)", flush=True)
            continue
        print(f"--- {time.strftime('%H:%M:%S')} ---", flush=True)
        for eid, e in sorted(entities.items()):
            hist = e["history"]
            if len(hist) >= 2:
                xs = set(h[1] for h in hist)
                ys = set(h[2] for h in hist)
                parado = "PARADO" if (len(xs) == 1 and len(ys) == 1) else "movendo"
            else:
                parado = "?"
            print(f"  id=0x{eid:04x}  x={e['x']:3d}  y={e['y']:3d}  [{parado}]  (amostras recentes: {len(hist)})", flush=True)
        print(flush=True)
except KeyboardInterrupt:
    print("\n[*] encerrado.", flush=True)
    session.detach()
