# Disypher

Classical cipher analysis. Paste an encrypted text and the engine tries every
known method, scores each result, and ranks the hypotheses by confidence —
without ever claiming to know when it doesn't.

No dependencies. Standard library only, so the same file runs in a terminal and
in a browser through WebAssembly.

## What it does

Fifteen ciphers, each with every one of its parameters exposed:

| Family | Methods |
|---|---|
| Substitution | Caesar, ROT5, ROT13, ROT18, ROT47, Atbash, Affine |
| Polyalphabetic | Vigenère, Beaufort |
| Transposition | Rail fence, Columnar, Reversed |
| Encoding | Base64, Hexadecimal, Binary, Morse |

Vigenère, Beaufort and columnar transposition are **broken without the key**.
Vigenère and Beaufort by estimating the period from the index of coincidence,
then solving each column; columnar by enumerating permutations, since only the
key's alphabetical ordering matters.

## Using it

```python
import cipher

report = cipher.analyse("Jnxr hc Arb. Gur Zngevk unf lbh.")
best = report.candidates[0]

best.cipher        # 'caesar'
best.params        # {'shift': 13}
best.plaintext     # 'Wake up Neo. The Matrix has you.'
best.confidence    # 0.80
report.reliable    # True
```

Narrow the search, or impose settings rather than searching for them:

```python
cipher.analyse(text, ["caesar", "affine"])
cipher.analyse(text, ["caesar"], {"caesar": {"shift": [3, 7, 13]}})
```

Encrypt through a chain, keeping every intermediate stage:

```python
cipher.encode_stages(text, [
    {"cipher": "caesar", "params": {"shift": 7}},
    {"cipher": "reverse"},
    {"cipher": "base64"},
])
```

From the command line:

```
python cipher.py "Jnxr hc Arb. Gur Zngevk unf lbh."
```

## Design principles

**It must be able to say "I don't know."** Twenty characters do not carry enough
information to choose between competing hypotheses. When the sample is too
short, when two candidates are too close, or when nothing convinces, the report
says so instead of ranking an invention first.

**Every parameter accepted when encrypting is accepted when decrypting.**
Otherwise the library can produce text it cannot read back.

**Nothing is truncated silently.** Every hypothesis and every alternative
setting is returned. A list cut at an arbitrary point gives the illusion of
exhaustiveness without offering it.

**The engine returns codes, not sentences.** Reasons come back as
`short_sample`, `already_plain`, `ambiguous` — never as prose. A library that
returns "Short sample" imposes its language on every interface built on it.

## Scoring

Three signals, each covering a weakness of the others:

- **chi-squared** on letter frequencies — reliable on long text, unmeasurable on
  short text. Its weight follows its own measurability rather than being counted
  as a failure when it cannot be computed;
- **the ratio of recognised words** — decisive on short text, blind to quantity;
- **the weight of recognised words**, where each match counts for its length.
  A random two-letter string has one chance in 676 of forming a given word; a
  seven-letter string, one in eight billion.

## Language banks

English and French are built in. Spanish, German, Italian and a technical
vocabulary bank ship as JSON files under `banks/` and load on demand:

```python
import json
cipher.load_bank(json.load(open("banks/es.json")))
```

More vocabulary means better recognition on short texts, and one more language
the engine can identify.

## Web interface

`index.html` runs the engine in a browser through
[Pyodide](https://pyodide.org). It loads `cipher.py` as-is rather than
reimplementing it in JavaScript, so the page cannot drift from the library.

Serve it over HTTP — opening the file directly will not work:

```
python -m http.server 8000
```

## Licence

MIT. See [LICENSE](LICENSE).
