"""Local model persistence: one directory per version (model.joblib + metadata.json) and an explicit
`active.json` pointer. Training never changes the active model; activating is a separate, explicit step.

Integrity: the model file's SHA-256 is recorded in metadata and checked on load, so a model file that was
replaced or corrupted is refused instead of unpickled. (Only load models from a directory you control.)
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

VERSION_RE = re.compile(r"^rf-v(\d+)$")


class ModelStoreError(RuntimeError):
    """The requested model is missing, unreadable or fails its integrity check."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ModelStore:
    def __init__(self, directory: Path) -> None:
        self._dir = Path(directory)

    @property
    def directory(self) -> Path:
        return self._dir

    def versions(self) -> list[dict[str, Any]]:
        """Metadata of every stored version, oldest first (unreadable entries are skipped)."""
        found = []
        if self._dir.is_dir():
            for path in self._dir.iterdir():
                match = VERSION_RE.match(path.name)
                meta = path / "metadata.json"
                if match and meta.is_file():
                    try:
                        found.append((int(match.group(1)), json.loads(meta.read_text(encoding="utf-8"))))
                    except (OSError, ValueError):
                        continue
        return [m for _, m in sorted(found, key=lambda x: x[0])]

    def next_version(self) -> str:
        numbers = [int(VERSION_RE.match(m["model_version"]).group(1)) for m in self.versions()]  # type: ignore[union-attr]
        return f"rf-v{max(numbers, default=0) + 1}"

    def save(self, model: Any, metadata: dict[str, Any]) -> dict[str, Any]:
        import joblib  # local import: only training / loading needs it

        version = metadata["model_version"]
        if not VERSION_RE.match(version):
            raise ModelStoreError(f"invalid model version '{version}'")
        target = self._dir / version
        if target.exists():
            raise ModelStoreError(f"model version '{version}' already exists (versions are never overwritten)")
        target.mkdir(parents=True)
        joblib.dump(model, target / "model.joblib")
        metadata = {**metadata, "model_sha256": _sha256(target / "model.joblib")}
        (target / "metadata.json").write_text(json.dumps(metadata, indent=1, default=str), encoding="utf-8")
        return metadata

    def metadata(self, version: str) -> dict[str, Any]:
        if not VERSION_RE.match(version):
            raise ModelStoreError(f"invalid model version '{version}'")
        path = self._dir / version / "metadata.json"
        if not path.is_file():
            raise ModelStoreError(f"model '{version}' not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def load(self, version: str) -> tuple[Any, dict[str, Any]]:
        import joblib

        meta = self.metadata(version)
        path = self._dir / version / "model.joblib"
        if not path.is_file():
            raise ModelStoreError(f"model file for '{version}' is missing")
        if _sha256(path) != meta.get("model_sha256"):
            raise ModelStoreError(f"model '{version}' failed its integrity check (file changed since training)")
        return joblib.load(path), meta

    # ------------------------------------------------------------- active model
    def active_version(self) -> str | None:
        pointer = self._dir / "active.json"
        if not pointer.is_file():
            return None
        try:
            version = json.loads(pointer.read_text(encoding="utf-8")).get("model_version")
        except (OSError, ValueError):
            return None
        return version if isinstance(version, str) and VERSION_RE.match(version) else None

    def set_active(self, version: str) -> None:
        self.metadata(version)  # must exist
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / "active.json").write_text(json.dumps({"model_version": version}), encoding="utf-8")
