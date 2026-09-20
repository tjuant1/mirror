"""
Captura mensagens de servidor (as amarelas no meio da tela, ex: "MEGAMU - O Comeco
de uma Nova Era!") gancho nos handlers Chat.* que recebem o payload ja decifrado.

Todos os handlers Chat.* sao ganchados para descobrir qual carrega o aviso amarelo;
o payload cru + texto decodificado sao impressos e salvos em server_notices.jsonl.

Uso: python frida_server_notice.py <PID> [segundos]   (0 = ate Ctrl+C)
"""
import sys
import time
import json
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PID = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 0
OUT = "server_notices.jsonl"

HANDLERS = [
    {"opcode": "C1:01", "cls": "Chat", "method": "IGHIAIGFCEP", "rva": "0x10AA200"},
    {"opcode": "C1:00", "cls": "Chat", "method": "ALIIEGLFLJK", "rva": "0x10AC9E0"},
    {"opcode": "C1:0D", "cls": "Chat", "method": "BMLFLDPDNDB", "rva": "0x10AD490"},
    {"opcode": "C1:F3:E4", "cls": "Chat", "method": "CHPMLAKAKKB", "rva": "0x10AF1A0"},
    {"opcode": "C1:0C", "cls": "Chat", "method": "LGFFMALBAGI", "rva": "0x10AFED0"},
    {"opcode": "C1:02", "cls": "Chat", "method": "CABGJPOLCMG", "rva": "0x10B0D50"},
]

JS = r"""
var gameBase = Process.getModuleByName("GameAssembly.dll").base;
var handlers = %s;
handlers.forEach(function (h) {
    Interceptor.attach(gameBase.add(parseInt(h.rva, 16)), {
        onEnter: function (args) {
            try {
                var p = args[0];
                if (p.isNull()) return;
                var len = p.add(0x18).readS32();
                if (len <= 0 || len > 4096) return;
                send({ opcode: h.opcode, method: h.method, len: len }, p.add(0x20).readByteArray(len));
            } catch (e) {}
        }
    });
});
send("hooks installed");
""" % json.dumps(HANDLERS)


def decode_text(raw):
    """Tenta extrair o texto do payload (header C1 size op [type] ...)."""
    body = raw[3:]
    if raw[2] == 0x0D:  # byte3 = tipo (0=aviso amarelo), zeros de padding, texto ate o NUL
        body = raw[4:].lstrip(bytes(1)).split(bytes(1))[0]
    for enc in ("utf-8", "cp1252", "utf-16-le"):
        try:
            return enc, body.decode(enc).replace("\x00", "").strip()
        except UnicodeDecodeError:
            continue
    return "raw", body.hex()


def on_message(message, data):
    if message["type"] != "send":
        print("[error]", message, flush=True)
        return
    p = message["payload"]
    if isinstance(p, str):
        print("[info]", p, flush=True)
        return
    raw = bytes(data)
    enc, text = decode_text(raw)
    rec = {"t": time.strftime("%H:%M:%S"), "opcode": p["opcode"], "method": p["method"],
           "hex": raw.hex(), "enc": enc, "text": text}
    print(f"[{rec['t']}] {p['opcode']} {p['method']} len={p['len']} [{enc}] {text!r}", flush=True)
    print(f"          hex={raw.hex()[:120]}", flush=True)
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


session = frida.attach(PID)
script = session.create_script(JS)
script.on("message", on_message)
script.load()
print(f"[*] escutando ({'ate Ctrl+C' if not DURATION else f'{DURATION}s'})...", flush=True)
try:
    time.sleep(DURATION) if DURATION else sys.stdin.read()
except KeyboardInterrupt:
    pass
session.detach()
