import json
import os
import pyghidra

GHIDRA_DLL = r"C:\Users\Juan-PC\AppData\Local\Programs\MEGAMU\bin\GameAssembly.dll"
PROJECT_LOCATION = r"C:\QA\apps\mirror\ghidra\project"
PROJECT_NAME = "megamu"
SCRIPT_JSON = r"C:\QA\apps\mirror\il2cppdumper\extracted\output\script.json"

# targets: (name_we_gave_it, rva_hex)
TARGETS = [
    ("NpcManager_C1_31", 0x11EB8E0),
    ("NpcManager_C2_31", 0x11F0DE0),
]

OUT_PATH = r"C:\QA\apps\mirror\ghidra\decompiled_targets.txt"

pyghidra.start()

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

with pyghidra.open_program(
    binary_path=GHIDRA_DLL,
    project_location=PROJECT_LOCATION,
    project_name=PROJECT_NAME,
    analyze=False,
    nested_project_location=False,
) as flat_api:
    program = flat_api.getCurrentProgram()
    base = program.getImageBase()
    USER_DEFINED = SourceType.USER_DEFINED

    print("Program:", program.getName())

    print("Loading script.json (this may take a bit, it's large)...")
    with open(SCRIPT_JSON, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    print("Loaded. ScriptMethod entries:", len(data.get("ScriptMethod", [])))

    tx_id = program.startTransaction("apply names")
    ok = False
    try:
        script_methods = data.get("ScriptMethod", [])
        count = 0
        for sm in script_methods:
            addr = base.add(sm["Address"])
            name = sm["Name"].replace(" ", "-")
            try:
                flat_api.createLabel(addr, name, True, USER_DEFINED)
            except Exception:
                pass
            # also make sure it's a function
            func = flat_api.getFunctionAt(addr)
            if func is None:
                try:
                    flat_api.createFunction(addr, None)
                except Exception:
                    pass
            count += 1
            if count % 20000 == 0:
                print(f"  ...{count}/{len(script_methods)} named")
        ok = True
    finally:
        program.endTransaction(tx_id, ok)

    try:
        program.save("apply il2cpp names", ConsoleTaskMonitor())
        print("Saved project with names applied.")
    except Exception as e:
        print("Save failed (continuing anyway):", e)

    # Now decompile our targets
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    with open(OUT_PATH, "w", encoding="utf-8") as out:
        for label, rva in TARGETS:
            addr = base.add(rva)
            func = flat_api.getFunctionAt(addr)
            out.write(f"\n{'='*80}\n{label} @ {addr}\n{'='*80}\n")
            if func is None:
                out.write("NO FUNCTION FOUND AT THIS ADDRESS\n")
                print(label, "-> no function found")
                continue
            out.write(f"Function name in Ghidra: {func.getName()}\n\n")
            result = decompiler.decompileFunction(func, 60, monitor)
            if result.decompileCompleted():
                out.write(result.getDecompiledFunction().getC())
            else:
                out.write("DECOMPILE FAILED: " + str(result.getErrorMessage()) + "\n")
            print(label, "-> decompiled")

    decompiler.dispose()

print("DONE. Output written to", OUT_PATH)
