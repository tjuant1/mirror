import sys, frida
s = frida.attach(int(sys.argv[1]))
js = open("tools/il2cpp_resolver.js", encoding="utf-8").read() + r"""
var cnt = F("il2cpp_image_get_class_count","uint32",["pointer"]), getc = F("il2cpp_image_get_class","pointer",["pointer","uint32"]),
    cname = F("il2cpp_class_get_name","pointer",["pointer"]), cns = F("il2cpp_class_get_namespace","pointer",["pointer"]);
rpc.exports.imgs = function(){ var o={}; for (var k in IMGS) o[k]=cnt(IMGS[k]); return o; };
rpc.exports.find = function(sub){ var o=[]; for (var k in IMGS){ var n=cnt(IMGS[k]); for(var i=0;i<n;i++){ var c=getc(IMGS[k],i); var nm=cname(c).readCString(); if(nm.toLowerCase().indexOf(sub.toLowerCase())>=0) o.push(k+"|"+cns(c).readCString()+"|"+nm);} } return o; };
"""
sc = s.create_script(js); sc.load()
print(sc.exports_sync.imgs())
for q in sys.argv[2:]: print(q, sc.exports_sync.find(q)[:40])
