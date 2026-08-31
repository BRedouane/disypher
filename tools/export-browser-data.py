"""Export language tables and bundled banks for the dependency-free browser engine."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("disypher_reference", ROOT / "disypher" / "__init__.py")
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)

languages = {
    code: {
        "code": entry.code,
        "name": entry.name,
        "frequencies": entry.frequencies,
        "words": sorted(entry.words),
        "builtin": entry.builtin,
    }
    for code, entry in module.LANGUAGES.items()
}
banks = {}
for path in sorted((ROOT / "disypher" / "banks").glob("*.json")):
    banks[path.stem] = json.loads(path.read_text(encoding="utf-8"))

payload = {"languages": languages, "banks": banks}
body = "window.DISYPHER_BROWSER_DATA=" + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + ";\n"
(ROOT / "browser-data.js").write_text(body, encoding="utf-8")
print(f"wrote browser-data.js ({len(body):,} characters)")
