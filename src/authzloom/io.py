from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import LimitExceeded
from .limits import Limits


def load_document(path: str | Path, limits: Limits | None = None) -> dict[str, Any]:
    path = Path(path)
    data = path.read_bytes()
    cap = (limits or Limits()).max_api_body_bytes
    if len(data) > cap:
        raise LimitExceeded("input or output exceeds configured limits")
    text = data.decode("utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("YAML needs the optional 'yaml' dependency; JSON works without extras") from exc
        return yaml.safe_load(text)
    import json
    return json.loads(text)
