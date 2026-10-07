"""uso: headless_run.py <log> <nick1> [nick2 ...]  (o 1o nick e a conta primaria que calibra)"""
import sys, threading, time, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rugard_gui as g
lock = threading.Lock(); f = open(sys.argv[1], "a", encoding="utf-8", buffering=1)
def log(n, m):
    with lock: f.write(f"{time.strftime('%H:%M:%S')} [{n}] {m}\n")
stop = threading.Event()
shared = {"lock": threading.Lock(), "event": threading.Event(), "cx": None, "cy": None, "set": False, "t_detect": None, "move_ready": threading.Event()}
tpl = g.load_confirm_template(g.CONFIRM_TEMPLATE_PATH)
ws = [g.AccountWorker(n, tpl, shared, log, stop, primary=(i == 0)) for i, n in enumerate(sys.argv[2:])]
for w in ws: w.start()
for w in ws: w.join()
log("*", "FIM")
