import sys, time, frida
pid=int(sys.argv[1]); k=int(sys.argv[2]); dx=int(sys.argv[3])
s=frida.attach(pid)
js=open("tools/il2cpp_resolver.js",encoding="utf-8").read()+r"""
var R=null;
function nf(k,r,a){return new NativeFunction(gm.base.add(R.rva[k]),r,a);}
function loc(){var b=nf("GET_LOCAL_BODY","pointer",[])(); var c=b.add(0x70).readPointer(); return [c.add(0x10).readS32(),c.add(0x14).readS32()];}
rpc.exports.pos=function(){R=rpc.exports.resolve(0);return loc();};
rpc.exports.mv=function(k,x,y){R=rpc.exports.resolve(k);
 var ik=R.rva.COORD_CTOR; var img=IMGS["Assembly-CSharp.dll"];
 var o=F("il2cpp_object_new","pointer",["pointer"])(gameClass("Coord"));
 nf("COORD_CTOR","void",["pointer","int","int"])(o,x,y);
 return nf("MOVE_TO","uint8",["pointer","pointer","float","pointer","uint8","uint8"])(nf("GET_LOCAL_BODY","pointer",[])(),o,1.0,ptr(0),0,0);};
"""
sc=s.create_script(js); sc.load()
p=sc.exports_sync.pos(); print("before",p)
print("ret",sc.exports_sync.mv(k,p[0]+dx,p[1]))
for _ in range(6):
    time.sleep(1.2); print("pos",sc.exports_sync.pos())
