# Disypher

Classical cipher analysis that refuses to guess.

Paste an encrypted text and the engine tries every known method, scores each
result, and ranks the hypotheses by confidence. When twenty characters are not
enough to choose, it says so rather than putting an invention first.

```
$ disypher "Jnxr hc Arb. Gur Zngevk unf lbh."

> ROT13          63%  shift 13  [en]
    Wake up Neo. The Matrix has you.

(6 more — use --top 7)
24 letters · index of coincidence 0.036 · 7 hypotheses
Short sample (24 letters). Statistical analysis is unreliable below 40 letters.
```

**Live demo:** [bredouane.github.io/disypher](https://bredouane.github.io/disypher/)
· **Install:** `pip install disypher` · No dependencies, standard library only.

## What makes it different

**It can say "I don't know."** Most tools rank something first no matter what.
This one reports a short sample, an ambiguous result or an already-readable
text as answers in their own right. A verdict you cannot trust is worse than no
verdict.

**Nothing is truncated silently.** Every hypothesis and every alternative
setting is returned. A list cut at an arbitrary point looks exhaustive without
being it — the reader stops wondering whether the answer was among the ones
hidden.

**Every parameter accepted when encrypting is accepted when decrypting.**
Otherwise the tool produces text it cannot read back. That symmetry is checked,
not assumed.

**It tells you what it did not touch.** ROT13 on a phone number leaves the
digits in the clear; Morse deletes punctuation and capitals for good. Both are
reported, on your text, measured rather than described.

**The documentation is measured, not written.** `disypher info` runs each
cipher on a probe text to determine whether it is its own inverse, which
character classes it changes, and what it destroys. A hand-written description
eventually contradicts the code.

## Ciphers

| Family | Methods |
|---|---|
| Substitution | Caesar, ROT5, ROT13, ROT18, ROT47, Atbash, Affine |
| Polyalphabetic | Vigenère, Beaufort |
| Transposition | Rail fence, Columnar, Reversed |
| Encoding | Base64, Hexadecimal, Binary, Morse |

Vigenère, Beaufort and columnar transposition are **broken without the key** —
the first two by estimating the period from the index of coincidence then
solving each column, the third by enumerating permutations, since only the
key's alphabetical ordering matters.

## Command line

```
disypher list                    every cipher, its family and its parameters
disypher banks                   loaded languages and their vocabulary
disypher info NAME               what one cipher does, measured from the code
disypher decrypt TEXT            analyse an encrypted text
disypher encrypt TEXT -c ...     encrypt through a chain
```

`disypher TEXT` on its own is a shortcut for `disypher decrypt TEXT`. If the
installed command is not on PATH — common on Windows — `python -m disypher`
always works.

### Decrypting

| Option | |
|---|---|
| `--only caesar,affine` | restrict the search to these ciphers |
| `--set caesar.shift=3,7,13` | impose a setting instead of searching for it; repeatable |
| `--top 7` | how many hypotheses to show |
| `--variants` | also list each hypothesis's alternative settings |
| `--bank es` | load a vocabulary bank; repeatable |
| `--peel N` | re-analyse hypothesis N instead of printing it |
| `--json` | the full report, machine-readable |

Long or multi-line messages come from standard input, which a shell would
otherwise mangle:

```
disypher decrypt - < message.txt
```

`--peel` strips one layer of a text encrypted several times over. Combine it
with `--only` when you know which layer comes first:

```
$ disypher encrypt "Wake up Neo" -c caesar:shift=7 -c reverse
> 2. reverse
    oaU wb lrhD

$ disypher decrypt "oaU wb lrhD" --only reverse --peel 1
> Caesar         83%  shift 7  [en]
    Wake up Neo
```

### Encrypting

Each `-c` adds one step, applied in order. Removing a step means not writing
it: a command line has no state to edit.

```
$ disypher encrypt "Attack at dawn, now!" -c caesar:shift=7 -c reverse -c base64 --stages

  1. caesar     shift=7
    Haahjr ha khdu, uvd!
  2. reverse
    !dvu ,udhk ah rjhaaH
> 3. base64
    IWR2dSAsdWRoayBhaCByamhhYUg=
```

Parameters follow the cipher name, separated by colons — `-c caesar:shift=7`,
`-c vigenere:key=lemon:autokey=true`. Colons rather than commas, because a
comma is itself a legitimate separator value: `-c "hex:sep=,"` has to remain
expressible.

Steps that lose or leak information say so:

```
$ disypher encrypt "Attack at dawn, now!" -c morse

> 1. morse
    .- - - .- -.-. -.- / .- - / -.. .- .-- -.
    ! permanently lost: punctuation, case
```

### Inspecting a cipher

```
$ disypher info railfence

RAILFENCE
  Classical transposition

  Family                transposition
  Encrypt parameters    rails=3, offset=0
  Decrypt settings      rails, offset
  Changes               letters, digits
  Own inverse           no
  Solved without a key  yes

HOW IT WORKS
  Here no letter is replaced. They are all kept; only their order changes.
  ...
    rail 1  A...C...D...
    rail 2  .T.A.K.T.A.N
    rail 3  ..T...A...W.

    read ->  ACDTAKTANTAW

HISTORY
  ...

SEE ALSO
  disypher info caesar, disypher info columnar
```

`--brief` stops after the table. Rail fence, columnar transposition and
Vigenère come with a diagram, since those three resist explanation in prose —
and the diagrams are drawn by running the engine, so they cannot depict
something the code no longer does.

Three ciphers accept different settings on each side, and `disypher list` shows
both columns:

| | Encrypt only | Decrypt only | Why |
|---|---|---|---|
| `columnar` | `pad` | `width` | padding is stripped on reading; width bounds the permutation search |
| `base64` | `urlsafe` | — | both alphabets are recognised automatically |
| `hex` | `upper` | — | hexadecimal reading is case-insensitive |

Parameter names are validated, so a typo is reported rather than silently
ignored.

## Library

```python
import disypher

report = disypher.analyse("Jnxr hc Arb. Gur Zngevk unf lbh.")
best = report.candidates[0]

best.cipher        # 'caesar'
best.params        # {'shift': 13}
best.plaintext     # 'Wake up Neo. The Matrix has you.'
best.confidence    # 0.63
report.reliable    # False — 24 letters is not enough
report.reason      # 'short_sample'
```

Reasons come back as codes rather than sentences, so any interface can render
them in its own language. `report.note` gives the English rendering.

```python
disypher.analyse(text, ["caesar", "affine"])
disypher.analyse(text, ["caesar"], {"caesar": {"shift": [3, 7, 13]}})

disypher.encode_stages(text, [
    {"cipher": "caesar", "params": {"shift": 7}},
    {"cipher": "reverse"},
    {"cipher": "base64"},
])

disypher.describe("vigenere")      # measured facts
disypher.CIPHER_NOTES["vigenere"]  # written notes and history
disypher.round_trip_loss(text, "morse")   # ['punctuation', 'case']
```

## How confidence is computed

Three signals, each covering a weakness of the others:

- **chi-squared** on letter frequencies — reliable on long text, unmeasurable
  on short text. Its weight follows its own measurability rather than being
  scored as a failure when it cannot be computed;
- **the ratio of recognised words** — decisive on short text, blind to
  quantity;
- **the weight of recognised words**, where each match counts for its length.
  A random two-letter string has one chance in 676 of forming a given word; a
  seven-letter string, one in eight billion.

It is a heuristic score between 0 and 1, not a probability, and the tool does
not pretend otherwise.

## Language banks

English and French are built in. Spanish, German, Italian and a technical
vocabulary bank ship with the package and load on demand:

```python
disypher.load_builtin_bank("es")
disypher.load_builtin_bank("technical")   # dev and unit vocabulary
```

`technical` is not a language: it holds terms such as "commit", "kg" or
"frontend" and extends every language already loaded rather than registering a
new one. More vocabulary means better recognition on short texts, and one more
language the engine can identify.

## Web interface

`index.html` runs the engine in the browser through
[Pyodide](https://pyodide.org). It fetches `disypher/__init__.py` as-is rather
than reimplementing it in JavaScript, so the page and the published package can
never drift apart. Serve it over HTTP:

```
python -m http.server 8000
```

## Scope

These are **classical** ciphers: historical, educational, and broken. Nothing
here protects anything, and none of it should be used to. The interesting part
is the analysis — deciding what a text is, and admitting when the evidence does
not support a decision.

## Licence

MIT. See [LICENSE](LICENSE).
