#!/usr/bin/env python3
"""Run one gmond Python metric module with given params, sampled on demand.

Usage: pymodule.py <module_dir> <module_name> <params-json>

Calls metric_init(params) and prints "READY" followed by one descriptor name
per line and "END". Then for every "sample" line on stdin it calls every
descriptor's call_back in order (one gmond collection pass) and prints
"name<TAB>repr(value)" lines and "END" ("ERR" if the callback raised).
"quit" or EOF exits. Used by the #[ignore] live parity tests in
src/collect/{diskstat,diskfree,procstat}.rs.
"""
import contextlib
import importlib
import io
import json
import logging
import sys
import types

moddir, modname, params = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
sys.path.insert(0, moddir)
# Stand-in for the builtin module gmond provides.
g = types.ModuleType('ganglia')
g.get_debug_msg_level = lambda: 0
sys.modules['ganglia'] = g
# Modules call logging.basicConfig at import (procstat truncates
# /tmp/gmond.log); a handler on the root logger makes that a no-op.
logging.basicConfig(handlers=[logging.NullHandler()])

m = importlib.import_module(modname)
descs = m.metric_init(params)
print("READY")
for d in descs:
    print(d['name'])
print("END", flush=True)

for line in sys.stdin:
    cmd = line.strip()
    if cmd == "quit":
        break
    if cmd != "sample":
        continue
    out = []
    for d in descs:
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                s = repr(d['call_back'](d['name']))
            except Exception:
                s = "ERR"
        out.append(f"{d['name']}\t{s}")
    out.append("END")
    print("\n".join(out), flush=True)

if hasattr(m, 'metric_cleanup'):
    m.metric_cleanup()
