# Make the package importable when the tests run from a plain checkout,
# with no install step - `python -m pytest tests` just works.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
