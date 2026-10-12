"""
Listener PASSIVO: registra o que o cliente faz quando voce clica no Rugard
e entra no evento (Doppelganger). So observa, nao envia nem altera nada.

Camadas gravadas:
  RX     pacotes recebidos (212 opcodes catalogados: classe.metodo)
  TX     pacotes enviados (ws2_32!send) + a cadeia de metodos do jogo que
         chamou o envio (resolvida contra addr_lookup.pkl)
  AWAKE  entidades que apareceram (Body.Awake)
  TRACE  (opcional, --trace) todos os metodos do jogo chamados na thread
         principal via Frida Stalker, descontando o que ja roda por frame
         na fase de baseline

Uso:
  python event_entry_listener.py <PID | parte do titulo da janela> [--baseline 4] [--duration 20] [--trace]

Fluxo: roda a fase BASELINE (nao mexa no jogo), o script avisa "AGORA",
ai voce clica no NPC, aparece o dialogo, aperta Enter e entra no evento.
Ctrl+C encerra antes. Relatorio em event_entry_report.txt.

Obs: --trace deixa o jogo mais lento enquanto grava; use so no tempo do teste.
Os RVAs valem para o build de 2026-09-18.
"""
import argparse
import bisect
import json
import os
import pickle
import sys
import time

import frida
import win32gui
import win32process

HERE = os.path.dirname(os.path.abspath(__file__))
AWAKE_RVA = 0xD2DF30
CAMERA_GET_MAIN_RVA = 0x464D920
INDEX_MAX = 10000

ap = argparse.ArgumentParser()
ap.add_argument("target", help="PID ou parte do titulo da janela (nick da conta)")
ap.add_argument("--baseline", type=float, default=4.0)
ap.add_argument("--duration", type=float, default=20.0)
ap.add_argument("--trace", action="store_true", help="liga o Stalker na thread principal")
args = ap.parse_args()


def resolve_pid(target):
    if target.isdigit():
        return int(target)
    found = []

    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and target.lower() in win32gui.GetWindowText(hwnd).lower():
            found.append(hwnd)

    win32gui.EnumWindows(cb, None)
    if not found:
        sys.exit(f"janela '{target}' nao encontrada")
    return win32process.GetWindowThreadProcessId(found[0])[1]


with open(os.path.join(HERE, "opcode_handlers.json")) as f:
    HANDLERS = json.load(f)
with open(os.path.join(HERE, "addr_lookup.pkl"), "rb") as f:
    ADDR_NAME = pickle.load(f)
ADDRS = [a for a, _ in ADDR_NAME]


def names_at(rva):
    i = bisect.bisect_right(ADDRS, rva) - 1
    if i < 0:
        return "?"
    a = ADDRS[i]
    lo = i
    while lo > 0 and ADDRS[lo - 1] == a:
        lo -= 1
    return " | ".join(n for _, n in ADDR_NAME[lo:i + 1][:3]) + (f"+0x{rva - a:x}" if rva != a else "")


JS = r"""
var gameMod = Process.getModuleByName("GameAssembly.dll");
var gb = gameMod.base;
var ge = gb.add(gameMod.size);
var t0 = Date.now();
var phase = 0;
var mainTid = null;
function now() { return Date.now() - t0; }
function inGame(p) { return p.compare(gb) >= 0 && p.compare(ge) < 0; }

function readStr(p) {
    try {
        if (p.isNull()) return null;
        var len = p.add(0x10).readS32();
        if (len < 0 || len > 256) return null;
        return p.add(0x14).readUtf16String(len);
    } catch (e) { return null; }
}

function noteMain() { if (mainTid === null) mainTid = Process.getCurrentThreadId(); }

// RX
var handlers = %%HANDLERS%%;
handlers.forEach(function (h) {
    try {
        Interceptor.attach(gb.add(parseInt(h.rva, 16)), {
            onEnter: function () { send({ k: "rx", p: phase, t: now(), op: h.opcode, cls: h.cls, m: h.method }); }
        });
    } catch (e) {}
});

// TX (ignora o keepalive de 1 byte)
var ws = Process.getModuleByName("ws2_32.dll");
Interceptor.attach(ws.getExportByName("send"), {
    onEnter: function (a) {
        var len = a[2].toInt32();
        if (len <= 1) return;
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        var rv = [];
        for (var i = 0; i < bt.length; i++) if (inGame(bt[i])) rv.push(bt[i].sub(gb).toUInt32());
        var hex = "";
        try {
            var b = new Uint8Array(a[1].readByteArray(Math.min(len, 32)));
            for (var j = 0; j < b.length; j++) hex += ("0" + b[j].toString(16)).slice(-2);
        } catch (e) {}
        send({ k: "tx", p: phase, t: now(), len: len, hex: hex, bt: rv });
    }
});

// AWAKE
Interceptor.attach(gb.add(%%AWAKE%%), {
    onEnter: function (a) {
        noteMain();
        var body = a[0], n = 0;
        var poll = function () {
            n++;
            try {
                var idx = body.add(0x20).readS32();
                if (idx >= %%INDEX_MAX%%) return;
                var name = readStr(body.add(0x28).readPointer());
                if (name === null) { if (n < 30) setTimeout(poll, 30); return; }
                send({ k: "awake", p: phase, t: now(), name: name, idx: idx });
            } catch (e) { if (n < 30) setTimeout(poll, 30); }
        };
        setTimeout(poll, 30);
    }
});
try { Interceptor.attach(gb.add(%%CAMERA%%), { onEnter: noteMain }); } catch (e) {}

// TRACE
var base = {}, act = {};
function rec(rva) {
    var m = phase === 0 ? base : act;
    var e = m[rva];
    if (e === undefined) m[rva] = { c: 1, t: now() }; else e.c++;
}

rpc.exports = {
    setPhase: function (p) { phase = p; return now(); },
    startTrace: function () {
        if (mainTid === null) return { error: "thread principal ainda nao identificada" };
        Stalker.follow(mainTid, {
            events: { call: true },
            onReceive: function (ev) {
                var evs = Stalker.parse(ev, { annotate: false, stringify: false });
                for (var i = 0; i < evs.length; i++) {
                    var tg = evs[i][2];
                    if (inGame(tg)) rec(tg.sub(gb).toUInt32());
                }
            }
        });
        return { ok: true, tid: mainTid };
    },
    stopTrace: function () {
        if (mainTid === null) return { base: base, act: act };
        Stalker.unfollow(mainTid);
        Stalker.flush();
        return { base: base, act: act };
    }
};
send({ k: "ready" });
""".replace("%%HANDLERS%%", json.dumps(HANDLERS)) \
   .replace("%%AWAKE%%", hex(AWAKE_RVA)) \
   .replace("%%CAMERA%%", hex(CAMERA_GET_MAIN_RVA)) \
   .replace("%%INDEX_MAX%%", str(INDEX_MAX))

events = []


def on_message(message, data):
    if message["type"] != "send":
        print("[frida-error]", message, flush=True)
        return
    p = message["payload"]
    if p.get("k") == "ready":
        return
    events.append(p)
    if p["p"] == 1 and p["k"] in ("tx", "awake"):
        if p["k"] == "tx":
            print(f"  [TX] len={p['len']} {p['hex'][:16]}...", flush=True)
        else:
            print(f"  [AWAKE] {p['name']} (idx={p['idx']})", flush=True)


pid = resolve_pid(args.target)
print(f"[*] anexando ao PID {pid}...", flush=True)
session = frida.attach(pid)
script = session.create_script(JS)
script.on("message", on_message)
script.load()

tracing = False
if args.trace:
    r = script.exports_sync.start_trace()
    if "error" in r:
        print(f"[!] trace nao iniciado: {r['error']} (mexa a camera/personagem e rode de novo)")
    else:
        tracing = True
        print(f"[*] Stalker ligado na thread principal (tid={r['tid']})", flush=True)

print(f"[*] BASELINE {args.baseline:.0f}s -- NAO mexa no jogo agora...", flush=True)
time.sleep(args.baseline)
t_phase2 = script.exports_sync.set_phase(1)
print(f"\n>>> AGORA: clique no Rugard, espere o dialogo, aperte Enter e entre no evento ({args.duration:.0f}s)\n", flush=True)
try:
    time.sleep(args.duration)
except KeyboardInterrupt:
    print("[*] encerrado por Ctrl+C", flush=True)

trace = {"base": {}, "act": {}}
if tracing:
    trace = script.exports_sync.stop_trace()
session.detach()

# ---------- relatorio ----------
base_ops = {}
for e in events:
    if e["p"] == 0 and e["k"] == "rx":
        base_ops[e["op"]] = base_ops.get(e["op"], 0) + 1

lines = []
w = lines.append
w("=== LINHA DO TEMPO (fase de acao; t em ms desde o AGORA) ===")
for e in sorted((x for x in events if x["p"] == 1), key=lambda x: x["t"]):
    t = e["t"] - t_phase2
    if e["k"] == "rx":
        if base_ops.get(e["op"], 0) >= 2:
            continue  # ruido de fundo (ja chegava parado)
        w(f"t={t:6d}  RX     {e['op']:<14} {e['cls']}.{e['m']}")
    elif e["k"] == "tx":
        w(f"t={t:6d}  TX     len={e['len']:<4} {e['hex']}")
        for rva in e["bt"][:8]:
            w(f"                  <- {names_at(rva)}")
    elif e["k"] == "awake":
        w(f"t={t:6d}  AWAKE  {e['name']} (idx={e['idx']})")

if tracing:
    base_set = set(int(k) for k in trace["base"])
    act = sorted(((v["t"], int(k), v["c"]) for k, v in trace["act"].items() if int(k) not in base_set))
    w("")
    w(f"=== TRACE: {len(act)} metodos do jogo chamados so na fase de acao "
      f"(descontados {len(base_set)} que ja rodavam no baseline) ===")
    by_cls = {}
    for t, rva, c in act:
        nm = names_at(rva)
        cls = nm.split("$$")[0]
        by_cls.setdefault(cls, []).append((t - t_phase2, nm, c))
    w("--- por classe (ordem da 1a chamada) ---")
    for cls, items in sorted(by_cls.items(), key=lambda kv: kv[1][0][0]):
        w(f"[{cls}]  {len(items)} metodo(s), 1a chamada em t={items[0][0]}ms")
        for t, nm, c in items[:12]:
            w(f"     t={t:6d}  x{c:<4} {nm}")

out = os.path.join(HERE, "event_entry_report.txt")
with open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print("\n".join(lines[:120]))
print(f"\n[*] relatorio completo em {out}")
