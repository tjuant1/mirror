import sys,time,frida
exec(open("tools/overload_matrix.py",encoding="utf-8").read().split("for k in range(5):")[0])
x0,y0=settle(); print("start",x0,y0,flush=True)
for dx,dy in ((5,0),(0,5),(-5,0),(0,-5),(12,0),(0,12),(-12,0),(0,-12)):
    res=[]
    for k in (0,2,4):
        x,y=settle()
        r=sc.exports_sync.mv(k,x0+dx,y0+dy); time.sleep(0.5)
        t0=time.time()
        while time.time()-t0<5:
            time.sleep(0.4); p=sc.exports_sync.pos()
            if abs(p[0]-(x0+dx))<=2 and abs(p[1]-(y0+dy))<=2: break
        res.append((k,r,"chegou" if abs(p[0]-(x0+dx))<=2 and abs(p[1]-(y0+dy))<=2 else "nao"))
        # volta ao inicio
        sc.exports_sync.mv(4,x0,y0); time.sleep(0.5); settle()
    print((dx,dy),res,flush=True)
