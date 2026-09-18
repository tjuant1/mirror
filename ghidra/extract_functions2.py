import pyghidra

GHIDRA_DLL = r"C:\Users\Juan-PC\AppData\Local\Programs\MEGAMU\bin\GameAssembly.dll"
PROJECT_LOCATION = r"C:\QA\apps\mirror\ghidra\project"
PROJECT_NAME = "megamu"

TARGETS = [
    ("Protocol_LDBBLKJDDAC", 0x134AAB0),
    ("Protocol_CPDIHOFIFNA", 0x134AB70),
    ("Protocol_HFOJAOGCHDP_a", 0x134AB90),
    ("Protocol_KKPFMLFCAPJ", 0x134C730),
    ("Protocol_JDHAOPFDLCM", 0x134F530),
    ("Protocol_LLLMBCNGBKF", 0x134F1F0),
    ("Protocol_PKODBMFFNMD", 0x134F270),
    ("Protocol_OIMGKHDDIEB", 0x134FE90),
    ("Protocol_HFOJAOGCHDP_b", 0x134DE70),
    ("Protocol_HFOJAOGCHDP_c", 0x134FFF0),
    ("GSConnection_MMCLLKMAPFK", 0x1345CC0),
]

OUT_PATH = r"C:\QA\apps\mirror\ghidra\decompiled_targets2.txt"

pyghidra.start()

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

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    with open(OUT_PATH, "w", encoding="utf-8") as out:
        for label, rva in TARGETS:
            addr = base.add(rva)
            func = flat_api.getFunctionAt(addr)
            out.write(f"\n{'='*80}\n{label} @ {addr}\n{'='*80}\n")
            if func is None:
                out.write("NO FUNCTION FOUND\n")
                print(label, "-> no function")
                continue
            out.write(f"Ghidra name: {func.getName()}\n\n")
            result = decompiler.decompileFunction(func, 60, monitor)
            if result.decompileCompleted():
                out.write(result.getDecompiledFunction().getC())
            else:
                out.write("DECOMPILE FAILED: " + str(result.getErrorMessage()) + "\n")
            print(label, "-> done")

    decompiler.dispose()

print("DONE:", OUT_PATH)
