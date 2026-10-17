#!/usr/bin/env python3
"""Drive a gmond Python metric module on command, for rgmond parity tests.

usage: driver.py MODULE_DIR MODULE PYCONF

Loads MODULE from MODULE_DIR with the params of PYCONF (parsed like gmond and
the scratchpad harness.py: every `param NAME { value = ... }`, as a string
with surrounding quotes stripped) and prints its descriptor names. Then for
each "sample" line on stdin, calls every callback once in descriptor order,
as gmond does, and prints the values. Protocol (stdout):

    names block:  NAME\\n ... END\\n
    sample block: T <time.time() before the first callback>\\n
                  NAME\\t<repr(float(value)) or None>\\n ... END\\n

Module output (the "is less 0" prints) goes to stderr.
"""
import importlib, os, re, sys, time, types

moddir, modname, pyconf = sys.argv[1:4]
sys.path.insert(0, moddir)
os.chdir(moddir)
g = types.ModuleType('ganglia'); g.get_debug_msg_level = lambda: 0; sys.modules['ganglia'] = g
proto, sys.stdout = sys.stdout, sys.stderr

params = {k: v.strip('"\'') for k, v in
          re.findall(r'^\s*param\s+(\S+)\s*\{\s*value\s*=\s*([^\n}]*?)\s*\}', open(pyconf).read(), re.M)}
m = importlib.import_module(modname)
descs = m.metric_init(params)
proto.write(''.join(d['name'] + '\n' for d in descs) + 'END\n'); proto.flush()

for line in sys.stdin:
    cmd = line.strip()
    if cmd == 'quit':
        break
    if cmd != 'sample':
        continue
    out = ['T %r\n' % time.time()]
    for d in descs:
        try:
            v = d['call_back'](d['name'])
            v = repr(float(v)) if isinstance(v, (int, float)) else 'None'
        except Exception:
            v = 'None'
        out.append('%s\t%s\n' % (d['name'], v))
    out.append('END\n')
    proto.write(''.join(out)); proto.flush()
