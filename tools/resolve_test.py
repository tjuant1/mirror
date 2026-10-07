import sys, json, frida
pid = int(sys.argv[1]); ordinal = int(sys.argv[2]) if len(sys.argv) > 2 else 0
s = frida.attach(pid)
sc = s.create_script(open(__file__.replace("resolve_test.py", "il2cpp_resolver.js"), encoding="utf-8").read())
sc.load()
print(json.dumps(sc.exports_sync.resolve(ordinal), indent=1))
