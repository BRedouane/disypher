from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("disypher_reference", ROOT / "disypher" / "__init__.py")
engine = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)

sample = "Attack the bridge at 06:30, now!"
vectors = [
    ("caesar", {"shift": 7}), ("rot13", {}), ("rot5", {}), ("rot18", {}),
    ("rot47", {"shift": 47}), ("atbash", {}), ("affine", {"a": 5, "b": 8}),
    ("vigenere", {"key": "disyner"}),
    ("vigenere", {"key": "key", "autokey": True}),
    ("beaufort", {"key": "disyner"}), ("reverse", {}),
    ("railfence", {"rails": 4, "offset": 2}),
    ("columnar", {"key": "zebra"}), ("base64", {}),
    ("hex", {"sep": ":", "prefix": "0x", "upper": True}),
    ("binary", {"sep": "-", "bits": 8}),
    ("morse", {"letter_sep": " ", "word_sep": " / "}),
]
analysis_cases = []
for cipher, params in vectors:
    analysis_name = "caesar" if cipher == "rot13" else cipher
    search_params = dict(params)
    search_params.pop("urlsafe", None)
    search_params.pop("upper", None)
    search_params.pop("pad", None)
    pinned = {analysis_name: search_params} if search_params else None
    encrypted = engine.encode(sample, cipher, **params)
    analysis_cases.append({
        "name": f"pinned-{cipher}",
        "text": encrypted,
        "only": [analysis_name],
        "params": pinned,
        "report": engine.analyse(encrypted, [analysis_name], pinned).as_dict(),
    })

default_text = "Jnxr hc Arb. Gur Zngevk unf lbh. Sbyybj gur juvgr enoovg. Xabpx xabpx."
analysis_cases.append({
    "name": "full-default-analysis",
    "text": default_text,
    "only": None,
    "params": None,
    "report": engine.analyse(default_text).as_dict(),
})

bank_cases = [
    ("es", "este mundo tiene una historia importante y cada persona puede encontrar una buena respuesta"),
    ("de", "diese welt hat eine wichtige geschichte und jeder mensch kann eine gute antwort finden"),
    ("it", "questo mondo ha una storia importante e ogni persona puo trovare una buona risposta"),
]
bank_reports = []
for code, plain in bank_cases:
    engine.load_builtin_bank(code)
    encrypted = engine.encode(plain, "caesar", shift=9)
    bank_reports.append({
        "code": code,
        "text": encrypted,
        "report": engine.analyse(encrypted, ["caesar"]).as_dict(),
    })
engine.load_builtin_bank("technical")

payload = {
    "sample": sample,
    "vectors": [
        {
            "cipher": cipher,
            "params": params,
            "encoded": engine.encode(sample, cipher, **params),
            "stages": engine.encode_stages(sample, [{"cipher": cipher, "params": params}]),
        }
        for cipher, params in vectors
    ],
    "analyses": analysis_cases,
    "banks": bank_reports,
}
(ROOT / "tests" / "reference.json").write_text(
    json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
)
print("wrote tests/reference.json")
