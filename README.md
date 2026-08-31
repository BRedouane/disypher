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
· **Portable web app:** download, unzip and open `index.html` · **Optional CLI:**
[`pip install disypher`](#installation-optional-cli) · No Python package dependencies.

## Private, portable web app

The downloaded web app runs entirely on the device. Unzip the folder and
double-click `index.html`: no server, Python installation, account or network
connection is required.

- input text is processed inside the browser;
- nothing is uploaded or saved by Disypher;
- no telemetry or remote font request is made;
- a dependency-free browser port and all language banks are bundled locally;
- a startup self-test validates cipher, encoding, Unicode and analysis behavior
  before the privacy badge receives its check mark;
- the same folder can also be served normally on the web.

Keep `index.html`, `browser-engine.js` and `browser-data.js` together. The
`disypher/` folder remains the Python/CLI reference implementation.

## Why the portable browser edition

Disypher originally ran its Python engine inside the browser through a
WebAssembly runtime. That preserved one implementation, but it also made the
web tool dependent on a comparatively large runtime and prevented a reliable
double-click workflow in browsers that restrict modules loaded from `file://`.

For the portable browser edition, we made a deliberate product decision:
**the web app must belong to the person using it, not to the machine hosting
it.** The browser engine is now a dependency-free JavaScript port of the Python
reference. It starts from ordinary local files, performs no automatic network
request and needs no local server.

This matters especially when the submitted text should not leave the device:

- penetration testers and security analysts may work with client data,
  captures and internal identifiers;
- students and CTF players should be able to start without installing Python
  or understanding virtual environments;
- teachers and workshop organisers can distribute one folder that works on an
  offline machine;
- occasional users can open the tool, solve one problem and close it without
  creating an account or leaving application data behind;
- developers still retain the Python package and CLI for scripting,
  automation and integration.

The two engines are not merely intended to behave alike. The Python
implementation is the reference, and automated parity fixtures compare all 17
public methods, their parameters and pipeline metadata, complete analyses and
the four optional language banks. The browser also runs 20 local startup
checks. Only after they pass does the interface display:

> **Processed locally · not saved ✓**

The check mark therefore means more than “the page loaded.” It confirms that
the local engine passed its cipher, encoding, Unicode and analysis checks. The
privacy statement describes the actual execution path: inputs remain in the
current browser page, Disypher does not transmit or persist them, and static
hosting serves files only.

The result is one project with two deliberate forms:

| Use case | Recommended form |
| --- | --- |
| Immediate, private or offline use | Open `index.html` |
| Public website | Serve the same folder as static files |
| Terminal, scripts and automation | Install the optional Python CLI |

---

**Contents** — [Private, portable web app](#private-portable-web-app) ·
[Why the portable browser edition](#why-the-portable-browser-edition) ·
[Why this exists](#why-this-exists) ·
[What makes it different](#what-makes-it-different) ·
[Installation](#installation-optional-cli) · [Ciphers](#ciphers) ·
[Command line](#command-line) ([decrypting](#decrypting),
[encrypting](#encrypting), [inspecting a cipher](#inspecting-a-cipher)) ·
[Library](#library) · [How confidence is computed](#how-confidence-is-computed) ·
[Language banks](#language-banks) · [Web interface](#web-interface) ·
[Scope](#scope) · [Licence](#licence)

---

## Why this exists

The tools that already exist do the job, and several do it very well. But using
one means knowing which one to reach for: choose the cipher, set the
parameters, assemble the recipe, read the output. That is a reasonable shape
when you already know what you are looking at.

It is the wrong shape entirely when you do not — and not knowing is the normal
case. An unknown string out of a capture, a CTF, or a client engagement does
not announce what it is.

Disypher inverts the order. **You supply the problem, not the procedure.** Paste
the text and the engine identifies, tries, scores and ranks on its own, with no
click required. Set a method by hand when you already know the answer and only
want it confirmed.

It was written by a penetration tester who kept running into that friction, for
the people who run into it too: analysts working through unknown data, CTF
players, and students who should not have to master a complicated interface
before decoding their first string.

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

## Installation (optional CLI)

Nothing needs to be installed for the web app. The instructions below are only
for people who want the command-line tool or the Python library.

**Requirement: Python 3.9 or newer.** Nothing else. The engine uses the
standard library only, so there is no dependency tree to resolve and nothing
that can break when some other package releases a new version.

Check what you have:

```
python --version
```

### Linux and macOS

```
pip install disypher
disypher --help
```

### Windows

`pip` and `python` are often missing from PATH on Windows, even after a normal
installation. The `py` launcher ships with every official Python installer and
is always reachable, so use it instead:

```
py -m pip install disypher
py -m disypher --help
```

After installing, try the bare `disypher` command. If your shell finds it, use
it — every example below is written that way. If it does not, `py -m disypher`
does exactly the same thing: the package ships a `__main__.py` for this case,
and no feature is lost through it.

### Checking it worked

```
$ disypher "Jnxr hc Arb. Gur Zngevk unf lbh."

> ROT13          63%  shift 13  [en]
    Wake up Neo. The Matrix has you.
```

If that prints, you are done.

### Upgrading and removing

```
pip install --upgrade disypher
pip uninstall disypher
```

### Without installing

You do not have to install anything to try it. The
[live demo](https://bredouane.github.io/disypher/) runs the browser edition —
a dependency-free JavaScript port of the Python engine, checked against it by
the parity suite. Download the folder and open `index.html` and you get the
same thing with no network at all. See
[the portable browser edition](#why-the-portable-browser-edition).

Installing the Python package is what you want for the command line, for
scripting, and for the reference implementation itself.

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
does the same, and `py -m disypher` when `python` is missing too. See
[Installation](#installation-optional-cli).

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

`index.html` loads the autonomous engine through ordinary local script tags.
It therefore works by double-clicking the file, fully offline, and behaves the
same on static hosting. No server is required. A server remains optional for
development or hosting:

```
python -m http.server 8000
```

Parity is checked against the Python reference with `tests/parity.cjs`: all 17
public methods, their pipeline metadata, full analyses, pinned parameters and
the four optional banks are compared as structured output.

## Scope

These are **classical** ciphers: historical, educational, and broken. Nothing
here protects anything, and none of it should be used to. The interesting part
is the analysis — deciding what a text is, and admitting when the evidence does
not support a decision.

The catalogue is narrower than the engine, and deliberately so for now. Several
encodings a security workflow meets often — Base32, Base85, URL and HTML
entities, Unicode escapes, XOR — are not implemented yet, and language
detection rests on word banks rather than n-grams, which shows on very short
samples. Multi-layer texts are peeled one layer at a time with `--peel`, not
unwound automatically.

This is a personal project, developed in the open and extended as it goes. The
honest summary is that the orchestration is further along than the coverage,
and that is the order it was built in on purpose: a wide catalogue that guesses
badly is worth less than a narrow one that knows when to stop.

## Licence

MIT. See [LICENSE](LICENSE).
