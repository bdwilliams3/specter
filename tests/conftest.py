import os
from pathlib import Path


os.environ.setdefault("SQLITE_PATH", str(Path(__file__).parent / "test_specter.db"))
