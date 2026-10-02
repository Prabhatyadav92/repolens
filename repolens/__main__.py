import sys

from .cli import main

try:
    code = main()
    sys.stdout.flush()
except BrokenPipeError:
    code = 0
raise SystemExit(code)
