"""
Resolucao em runtime dos enderecos do jogo -- substitui RVAs fixos que quebravam a cada update.

Tudo e achado via API exportada do IL2CPP (nome de classe, nomes NAO ofuscados da Unity /
Body.Awake, e assinatura de tipos), entao sobrevive a updates do cliente. A unica coisa que nao
da pra achar so por assinatura e QUAL dos 5 overloads identicos de LocalCharacterBody
(Coord,float,UnityAction,bool,bool)->bool e o "andar ate la" de verdade; isso e calibrado UMA vez
por build (andando o personagem 4 tiles) e guardado em rva_cache.json.
"""
import json
import os
import sys
import threading
import time

import frida

RESOLVER_JS = r'''
// Resolve em runtime os enderecos usados pela automacao, via API exportada do IL2CPP.
// Nada aqui depende de RVA nem de nome ofuscado de metodo: usa nomes de classe,
// nomes de metodos/campos NAO ofuscados (Unity + Body.Awake) e assinaturas de tipos.
var gm = Process.getModuleByName("GameAssembly.dll");
function F(n, r, a) { return new NativeFunction(gm.getExportByName(n), r, a); }
var api = {
  domain_get: F("il2cpp_domain_get", "pointer", []),
  get_assemblies: F("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]),
  asm_image: F("il2cpp_assembly_get_image", "pointer", ["pointer"]),
  image_name: F("il2cpp_image_get_name", "pointer", ["pointer"]),
  class_from_name: F("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]),
  get_methods: F("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]),
  m_name: F("il2cpp_method_get_name", "pointer", ["pointer"]),
  m_pcount: F("il2cpp_method_get_param_count", "uint32", ["pointer"]),
  m_param: F("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]),
  m_ret: F("il2cpp_method_get_return_type", "pointer", ["pointer"]),
  m_flags: F("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]),
  t_name: F("il2cpp_type_get_name", "pointer", ["pointer"]),
  field_by_name: F("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]),
  field_off: F("il2cpp_field_get_offset", "int", ["pointer"]),
};
function cs(s) { return Memory.allocUtf8String(s); }
function images() {
  var sz = Memory.alloc(8), arr = api.get_assemblies(api.domain_get(), sz), n = sz.readU64().toNumber(), out = {};
  for (var i = 0; i < n; i++) { var img = api.asm_image(arr.add(i * Process.pointerSize).readPointer()); out[api.image_name(img).readCString()] = img; }
  return out;
}
var IMGS = images();
var cnt = F("il2cpp_image_get_class_count", "uint32", ["pointer"]), getc = F("il2cpp_image_get_class", "pointer", ["pointer", "uint32"]),
    cname = F("il2cpp_class_get_name", "pointer", ["pointer"]);
var GAME = null;  // nome -> classe, so Assembly-CSharp (ignora namespace: era "" e virou "Mega")
function gameClass(name) {
  if (GAME === null) {
    GAME = {}; var img = IMGS["Assembly-CSharp.dll"], n = cnt(img);
    for (var i = 0; i < n; i++) { var c = getc(img, i), nm = cname(c).readCString(); if (!(nm in GAME)) GAME[nm] = c; }
  }
  return GAME[name] || ptr(0);
}
function findClass(ns, name) {
  if (ns === "") return gameClass(name);
  for (var k in IMGS) { var c = api.class_from_name(IMGS[k], cs(ns), cs(name)); if (!c.isNull()) return c; }
  return ptr(0);
}
function methods(klass) {
  var it = Memory.alloc(8); it.writePointer(ptr(0)); var out = [];
  for (;;) {
    var m = api.get_methods(klass, it); if (m.isNull()) break;
    var pc = api.m_pcount(m), ps = [];
    for (var i = 0; i < pc; i++) ps.push(api.t_name(api.m_param(m, i)).readCString());
    out.push({ name: api.m_name(m).readCString(), params: ps, ret: api.t_name(api.m_ret(m)).readCString(),
               isStatic: (api.m_flags(m, ptr(0)) & 0x10) !== 0, addr: m.readPointer() });  // MethodInfo->methodPointer @ +0
  }
  return out;
}
function rva(a) { return "0x" + a.sub(gm.base).toString(16); }
function byName(ns, cls, name, nparams) {
  var c = findClass(ns, cls); if (c.isNull()) return null;
  var r = methods(c).filter(function (m) { return m.name === name && (nparams === undefined || m.params.length === nparams); });
  return r.length ? r : null;
}
function sig(m, sigParams, ret, wantStatic) {
  if (m.params.length !== sigParams.length || m.isStatic !== wantStatic) return false;
  if (ret && m.ret !== ret && !(ret[0] === "*" && m.ret.slice(-ret.length + 1) === ret.slice(1))) return false;
  for (var i = 0; i < sigParams.length; i++) { var w = sigParams[i], p = m.params[i]; if (p !== w && !(w[0] === "*" && p.slice(-w.length + 1) === w.slice(1))) return false; }
  return true;
}
rpc.exports = {
  resolve: function (moveOrdinal) {
    var res = {}, miss = [];
    function put(k, v) { if (v) res[k] = v; else miss.push(k); }
    var a = byName("", "Body", "Awake", 0);                       put("AWAKE", a && a[0].addr);
    var c = byName("", "Coord", ".ctor", 2); c = c && c.filter(function (m) { return m.params.join() === "System.Int32,System.Int32"; });
    put("COORD_CTOR", c && c.length && c[0].addr);
    var cm = byName("UnityEngine", "Camera", "get_main", 0);      put("CAMERA_GET_MAIN", cm && cm[0].addr);
    var w = byName("UnityEngine", "Camera", "WorldToScreenPoint_Injected", 3); put("CAMERA_W2S_INJECTED", w && w[0].addr);
    var sw = byName("UnityEngine", "Screen", "get_width", 0);     put("SCREEN_W", sw && sw[0].addr);
    var sh = byName("UnityEngine", "Screen", "get_height", 0);    put("SCREEN_H", sh && sh[0].addr);
    var gc = findClass("", "GameContext");
    if (!gc.isNull()) {
      var g = methods(gc).filter(function (m) { return sig(m, [], "*LocalCharacterBody", true); });
      put("GET_LOCAL_BODY", g.length && g[0].addr); res._getLocalCandidates = g.length;
    } else miss.push("GET_LOCAL_BODY");
    var lc = findClass("", "LocalCharacterBody");
    if (!lc.isNull()) {
      var mv = methods(lc).filter(function (m) { return sig(m, ["*Coord", "System.Single", "UnityEngine.Events.UnityAction", "System.Boolean", "System.Boolean"], "System.Boolean", false); });
      res._moveCandidates = mv.map(function (m) { return rva(m.addr); });
      put("MOVE_TO", mv.length > moveOrdinal && mv[moveOrdinal].addr);
    } else miss.push("MOVE_TO");
    var body = findClass("", "Body"), off = {};
    ["Index", "Name", "TargetCoordinates", "Position"].forEach(function (f) {
      var fl = body.isNull() ? ptr(0) : api.field_by_name(body, cs(f));
      off[f] = fl.isNull() ? null : api.field_off(fl);
    });
    var out = { rva: {}, missing: miss, offsets: off, move_candidates: res._moveCandidates, getlocal_candidates: res._getLocalCandidates };
    for (var k in res) if (k[0] !== "_") out.rva[k] = rva(res[k]);
    return out;
  },
  dllPath: function () { return gm.path; },
  dumpClassMethods: function (ns, cls) { var c = findClass(ns, cls); return c.isNull() ? null : methods(c).map(function (m) { return m.name + "(" + m.params.join(",") + ")->" + m.ret + (m.isStatic ? " static " : " ") + rva(m.addr); }); }
};
'''

MOVE_CANDIDATES = 5


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


CACHE_PATH = os.path.join(_base_dir(), "rva_cache.json")

_CALIB_JS = RESOLVER_JS + r'''
var R = null;
function nf(k, r, a) { return new NativeFunction(gm.base.add(R.rva[k]), r, a); }
rpc.exports.pos = function () {
  var R0 = rpc.exports.resolve(0); R = R0;
  var b = nf("GET_LOCAL_BODY", "pointer", [])(); var c = b.add(0x70).readPointer();
  return [c.add(0x10).readS32(), c.add(0x14).readS32()];
};
rpc.exports.mv = function (k, x, y) {
  R = rpc.exports.resolve(k);
  var o = F("il2cpp_object_new", "pointer", ["pointer"])(gameClass("Coord"));
  nf("COORD_CTOR", "void", ["pointer", "int", "int"])(o, x, y);
  return nf("MOVE_TO", "uint8", ["pointer", "pointer", "float", "pointer", "uint8", "uint8"])(nf("GET_LOCAL_BODY", "pointer", [])(), o, 1.0, ptr(0), 0, 0);
};
'''


def _dll_key(pid_or_path):
    p = pid_or_path
    st = os.stat(p)
    return "%d-%d" % (st.st_size, int(st.st_mtime))


def _load_cache():
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _cached_ordinal(key):
    e = _load_cache().get(key, {})
    return e.get("move_ordinal") if e.get("cal_version") == CAL_VERSION else None


def _save_cache(c):
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(c, f, indent=1)
    except Exception:
        pass


CAL_VERSION = 2  # sobe quando o criterio de calibracao muda (invalida caches antigos)


def calibrate_move(session, log=print):
    """Acha qual overload e o 'andar ate la' MAIS CONFIAVEL. Move o personagem ~4 tiles (ele precisa estar parado).

    Testa todos os overloads em 4 direcoes e escolhe o que mais vezes (>=3 de 4) retorna 0 (enfileirou) E chega.
    Visto ao vivo: o overload que passa em 2 direcoes pode devolver 1 (nao anda) em outras situacoes;
    so o mais consistente serve."""
    sc = session.create_script(_CALIB_JS)
    sc.load()
    best_k, best_score = None, 0
    try:
        for k in range(MOVE_CANDIDATES):
            score, fails = 0, 0
            for dx, dy in ((4, 0), (-4, 0), (0, 4), (0, -4)):
                x0, y0 = sc.exports_sync.pos()
                tx, ty = x0 + dx, y0 + dy
                ret = sc.exports_sync.mv(k, tx, ty)
                arrived = False
                if ret == 0:                      # so vale esperar se o comando foi enfileirado
                    t0 = time.time()
                    while time.time() - t0 < 5:
                        time.sleep(0.4)
                        x1, y1 = sc.exports_sync.pos()
                        if max(abs(x1 - tx), abs(y1 - ty)) <= 1:
                            arrived = True
                            break
                log("calibrando overload %d: dir=(%d,%d) ret=%s chegou=%s" % (k, dx, dy, ret, arrived))
                if arrived:
                    score += 1
                else:
                    fails += 1
                    if fails >= 2:                # nao chega mais a 3/4
                        break
            if score > best_score:
                best_k, best_score = k, score
            if score == 4:
                break
        return best_k if best_score >= 3 else None
    finally:
        sc.unload()


_CAL_LOCK = threading.Lock()  # so uma conta calibra por vez (as outras reaproveitam o cache)


def _resolve_once(session, ordinal):
    sc = session.create_script(RESOLVER_JS)
    sc.load()
    try:
        out = sc.exports_sync.resolve(ordinal if ordinal is not None else 0)
        out["dll_key"] = _dll_key(sc.exports_sync.dll_path())
    finally:
        sc.unload()
    out["move_ordinal"] = ordinal
    if out["missing"]:
        raise RuntimeError("nao consegui resolver: %s" % ", ".join(out["missing"]))
    for k, v in out["offsets"].items():
        if v is None:
            raise RuntimeError("campo Body.%s nao encontrado" % k)
    return out


def resolve_all(session, log=print, allow_calibrate=True):
    """Retorna dict com rva (hex str) de AWAKE, COORD_CTOR, CAMERA_*, SCREEN_*, GET_LOCAL_BODY, MOVE_TO e offsets de campo.

    allow_calibrate=False: nao mexe no personagem; usa o overload do cache (ou 0 se ainda nao calibrado,
    ver out["move_ordinal"] is None) -- depois chame ensure_move() para calibrar/aplicar."""
    out = _resolve_once(session, None)
    ordinal = _cached_ordinal(out["dll_key"])
    if ordinal is None and allow_calibrate:
        out = ensure_move(session, out, log)
    elif ordinal is not None:
        out = _resolve_once(session, ordinal)
    return out


def ensure_move(session, resolved, log=print, primary=True, ready=None, wait_timeout=180):
    """Garante que o overload de movimento esta calibrado para este build e devolve `resolved` atualizado.

    primary=True: esta conta calibra (anda o personagem ~4 tiles; precisa estar parado), grava o cache e seta `ready`.
    primary=False: espera `ready` (a conta primaria terminar) e reaproveita o cache; so calibra por conta propria
    se a primaria falhar. Uma trava global garante que nunca calibram duas contas ao mesmo tempo."""
    key = resolved["dll_key"]
    try:
        ordinal = _cached_ordinal(key)
        if ordinal is None and not primary and ready is not None:
            log("aguardando a conta primaria calibrar o movimento...")
            ready.wait(wait_timeout)
            ordinal = _cached_ordinal(key)
        if ordinal is None:
            with _CAL_LOCK:
                ordinal = _cached_ordinal(key)  # outra conta pode ter acabado de gravar
                if ordinal is None:
                    log("build novo detectado -- calibrando a funcao de movimento (personagem precisa estar parado)...")
                    ordinal = calibrate_move(session, log)
                    if ordinal is not None:
                        cache = _load_cache()
                        cache[key] = {"move_ordinal": ordinal, "cal_version": CAL_VERSION}
                        _save_cache(cache)
                        log("movimento calibrado: overload %d (salvo em rva_cache.json)" % ordinal)
        elif primary:
            log("movimento ja calibrado para este build (overload %d)" % ordinal)
    finally:
        if primary and ready is not None:
            ready.set()
    if ordinal is None:
        log("!!! aviso: movimento NAO calibrado; usando overload 0 (pode nao funcionar)")
        return resolved
    return _resolve_once(session, ordinal)
