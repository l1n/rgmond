#!/usr/bin/env python3
"""Drive one gmond Python metric module the way gmond does, on demand.

Usage: driver.py <module_dir> <module_name>

Loads the module, calls metric_init({}) and prints "READY". Then for every
line "sample" read on stdin it calls each descriptor's call_back in
descriptor order (as one gmond collection pass would) and prints one
"name<TAB>value" line per metric followed by "END". A callback that raises
prints "ERR" as its value (gmond sends 0 in that case). "quit" or EOF exits.
Used by the #[ignore] live parity tests in src/collect/*.rs.
"""
import contextlib
import importlib
import io
import sys
import types

moddir, modname = sys.argv[1], sys.argv[2]
sys.path.insert(0, moddir)
# Stand-in for the builtin module gmond provides.
g = types.ModuleType('ganglia')
g.get_debug_msg_level = lambda: 0
sys.modules['ganglia'] = g

m = importlib.import_module(modname)
descs = m.metric_init({})
print("READY", flush=True)

for line in sys.stdin:
    cmd = line.strip()
    if cmd == "quit":
        break
    if cmd != "sample":
        continue
    out = []
    for d in descs:
        # Modules print() diagnostics ("x is less 0"); keep stdout clean.
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                v = d['call_back'](d['name'])
                s = v if isinstance(v, str) else repr(v)
            except Exception:
                s = "ERR"
        out.append(f"{d['name']}\t{s}")
    out.append("END")
    print("\n".join(out), flush=True)

if hasattr(m, 'metric_cleanup'):
    m.metric_cleanup()
