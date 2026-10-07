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
  dumpClassMethods: function (ns, cls) { var c = findClass(ns, cls); return c.isNull() ? null : methods(c).map(function (m) { return m.name + "(" + m.params.join(",") + ")->" + m.ret + (m.isStatic ? " static " : " ") + rva(m.addr); }); }
};
