import sys, time, frida
pid=int(sys.argv[1])
s=frida.attach(pid)
js=open("tools/il2cpp_resolver.js",encoding="utf-8").read()+r"""
var R=null;
function nf(k,r,a){return new NativeFunction(gm.base.add(R.rva[k]),r,a);}
function loc(){var b=nf("GET_LOCAL_BODY","pointer",[])(); var c=b.add(0x70).readPointer(); return [c.add(0x10).readS32(),c.add(0x14).readS32()];}
rpc.exports.pos=function(){R=rpc.exports.resolve(0);return loc();};
rpc.exports.mv=function(k,x,y){R=rpc.exports.resolve(k);
 var o=F("il2cpp_object_new","pointer",["pointer"])(gameClass("Coord"));
 nf("COORD_CTOR","void",["pointer","int","int"])(o,x,y);
 return nf("MOVE_TO","uint8",["pointer","pointer","float","pointer","uint8","uint8"])(nf("GET_LOCAL_BODY","pointer",[])(),o,2.0,ptr(0),0,0);};
"""
sc=s.create_script(js); sc.load()
def settle():
    last=None
    for _ in range(20):
        p=sc.exports_sync.pos()
        if p==last: return p
        last=p; time.sleep(1)
    return last
for k in range(5):
    row=[]
    for dx,dy in ((5,0),(-5,0),(0,5),(0,-5)):
        x0,y0=settle()
        ret=sc.exports_sync.mv(k,x0+dx,y0+dy)
        t0=time.time(); x1,y1=x0,y0
        while time.time()-t0<6:
            time.sleep(0.4); x1,y1=sc.exports_sync.pos()
            if max(abs(x1-x0-dx),abs(y1-y0-dy))<=2: break
        row.append("ret=%s dist_final=%d"%(ret,max(abs(x1-x0-dx),abs(y1-y0-dy))))
    print("overload",k,row,flush=True)
