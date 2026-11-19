import os
import tempfile
from pathlib import Path

# Keep test events out of the real artifacts/sentinelloop.db.
_TMP = Path(tempfile.mkdtemp(prefix="sentinelloop-tests-"))
os.environ["SENTINELLOOP_DATABASE_URL"] = f"sqlite:///{(_TMP / 'events.db').as_posix()}"
for name in ("SENTINELLOOP_UPSTREAM_URL", "SENTINELLOOP_API_KEY", "SENTINELLOOP_RULES_PATH"):
    os.environ.pop(name, None)
