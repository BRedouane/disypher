"""
Support for `python -m disypher`, alongside the installed `disypher` command.

Both entry points matter. The console script is the convenient one, but it
lands in the interpreter's scripts directory, which is not always on PATH —
notably on Windows when Python was installed without the option ticked. The
module form always works, because it goes through the interpreter itself.
"""

from . import _cli

raise SystemExit(_cli())
