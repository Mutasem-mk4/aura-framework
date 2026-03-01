import traceback, sys
sys.path.append('.')
from aura.cli import cli

try:
    cli(['zenith', 'zero.webappsecurity.com'])
except Exception:
    import builtins
    builtins.open('error_trace.log', 'w', encoding='utf-8').write(traceback.format_exc())
