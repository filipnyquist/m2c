"""mitmdump script shim: `mitmdump -s .../m2c/entry.py --set proxyauth=any`.

Only `addons` is defined here: module-level functions named like hooks would fire as well.
"""

import sys
from pathlib import Path

try:
    from m2c.recorder import Recorder
except ImportError:  # run from a source tree or bundle that is not on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from m2c.recorder import Recorder

addons = [Recorder()]
