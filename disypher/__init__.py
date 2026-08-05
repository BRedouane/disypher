"""
Disypher — classical cipher analysis.

The engine does not "decode": it **ranks hypotheses**. For a given text it
tries every known cipher, scores each result, and returns the candidates
ordered by confidence.

Three principles govern this file:

1. **It must be able to say "I don't know."** Twenty characters do not carry
   enough information to choose between competing hypotheses. Returning a
   top-ranked answer anyway would be an invention.

2. **Every cipher exposes all of its parameters.** A rail fence has a rail
   count *and* a starting offset; a hexadecimal encoding has a separator and a
   prefix. A library that exposes only the main parameter forces its callers to
   work around it. Anything accepted when encrypting is accepted when
   decrypting.

3. **No dependencies.** Standard library only, so the same file runs in a
   terminal and in a browser through WebAssembly.
"""
from __future__ import annotations

import base64
import binascii
import itertools
import json as _json
import math
import re
from dataclasses import dataclass, field

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Language registry
# ---------------------------------------------------------------------------
#
# Languages are registered objects rather than hard-coded tables, and more can
# be added at runtime — from a file, from a call, from a web page. Three
# reasons:
#
# 1. Recognition accuracy depends directly on the size of the known vocabulary.
#    On a short text it is the *only* signal that counts, so freezing the list
#    in the source caps the library's precision permanently.
#
# 2. One more language is one more language that can be identified. The engine
#    answers not just "this is a Caesar" but "this is a Caesar, and the result
#    is Spanish".
#
# 3. Full word lists are large. Keeping them outside leaves the module light by
#    default and accurate on demand.

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


@dataclass
class Language:
    """A reference language: its letter frequencies and its vocabulary."""

    code: str
    name: str
    # Published percentage frequency of each letter.
    frequencies: dict
    # Common words. Single-letter words are ignored in use: they occur by
    # chance in any scrambled text and would create false matches.
    words: set
    # True for languages shipped with the library, false for caller-supplied
    # ones. Display only.
    builtin: bool = True


LANGUAGES: dict = {}


def register_language(
    code: str,
    name: str,
    frequencies: dict,
    words,
    builtin: bool = False,
) -> Language:
    """
    Add or replace a reference language.

    Frequencies are expected as percentages. Missing letters default to zero,
    which suits languages that do not use the whole Latin alphabet — Italian
    has no native k, w, x or y.
    """
    table = {letter: float(frequencies.get(letter, 0.0)) for letter in ALPHABET}
    entry = Language(
        code=code,
        name=name,
        frequencies=table,
        words={w.strip().lower() for w in words if len(w.strip()) > 1},
        builtin=builtin,
    )
    LANGUAGES[code] = entry
    return entry


def load_bank(bank: dict) -> str:
    """
    Load a bank, whether it describes a language or a shared supplement.

    A bank flagged `universal` is **not** a language. Technical terms such as
    "commit", "kg" or "frontend" belong to none in particular: registering them
    as a separate language would create a rival with no grammar and no letter
    frequencies, which would win detection on any text containing two of them.
    Such words therefore extend **every** known language at once, which is also
    the linguistic truth.

    Returns a short summary of what was done.
    """
    if bank.get("universal"):
        added = {code: extend_words(code, bank["words"]) for code in list(LANGUAGES)}
        return "+" + ", ".join(f"{n} {code}" for code, n in added.items())
    entry = register_language(
        bank["code"], bank["name"], bank.get("frequencies", {}), bank["words"]
    )
    return f"{entry.code}: {len(entry.words)}"


# Vocabulary banks shipped inside the package. Loading one is optional: the
# module works with English and French alone, and each bank adds recognition
# accuracy plus one more language the engine can identify.
BUILTIN_BANKS = ("es", "de", "it", "technical")

# The technical bank is stored under its historical file name.
_BANK_FILES = {"technical": "universal.json"}


def load_builtin_bank(code: str) -> str:
    """
    Load one of the banks distributed with the package.

    Reading them through `importlib.resources` rather than a path built from
    `__file__` is what makes them work once installed: pip may place the
    package inside a zip archive, where no filesystem path exists.

        >>> import disypher
        >>> disypher.load_builtin_bank("es")

    `technical` is not a language. It holds development and unit vocabulary —
    "commit", "kg", "frontend" — and extends every language already loaded
    rather than registering a new one.
    """
    if code not in BUILTIN_BANKS:
        raise ValueError(
            f"unknown bank {code!r}; available: {', '.join(BUILTIN_BANKS)}"
        )
    name = _BANK_FILES.get(code, f"{code}.json")
    try:
        from importlib import resources

        raw = resources.files(__package__).joinpath("banks", name).read_text("utf-8")
    except (ImportError, AttributeError, TypeError):
        # Python 3.8 and standalone use, where the module is not a package.
        import os

        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "banks", name), encoding="utf-8") as handle:
            raw = handle.read()
    return load_bank(_json.loads(raw))


def extend_words(code: str, words) -> int:
    """
    Extend the vocabulary of a known language, leaving the rest untouched.

    Returns the number of words actually added, so that a load which brings
    nothing new can be seen rather than assumed.
    """
    language = LANGUAGES[code]
    before = len(language.words)
    language.words.update(
        w.strip().lower() for w in words if len(w.strip()) > 1
    )
    return len(language.words) - before


register_language(
    "en", "English",
    {
        "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23,
        "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03,
        "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99,
        "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
        "y": 1.97, "z": 0.07,
    },
    {
        "about", "above", "act", "add", "after", "again", "ago", "air", "all",
        "also", "always", "among", "an", "and", "animal", "answer", "any", "are",
        "area", "as", "ask", "at", "back", "base", "be", "because", "been",
        "before", "began", "begin", "being", "between", "big", "bird", "black",
        "blue", "boat", "body", "book", "both", "boy", "bring", "brought", "build",
        "busy", "but", "by", "call", "came", "can", "car", "care", "carry",
        "cause", "change", "check", "children", "city", "class", "close", "color",
        "come", "common", "complete", "could", "country", "course", "cover",
        "cross", "cut", "day", "decide", "deep", "did", "differ", "direct",
        "distant", "do", "does", "dog", "dont", "door", "down", "draw", "dry",
        "each", "earth", "ease", "east", "eat", "end", "enough", "equate", "even",
        "ever", "every", "example", "eye", "face", "family", "far", "father",
        "feel", "feet", "few", "fill", "find", "fire", "first", "fish", "follow",
        "food", "foot", "for", "force", "form", "found", "four", "friend", "from",
        "full", "game", "get", "girl", "give", "go", "gold", "good", "got",
        "great", "group", "grow", "had", "half", "hand", "happen", "hard", "has",
        "have", "he", "head", "hear", "heat", "hello", "help", "her", "here",
        "high", "him", "his", "home", "horse", "hot", "house", "how", "idea", "if",
        "in", "inch", "into", "is", "island", "it", "its", "just", "keep", "kind",
        "king", "knew", "know", "land", "language", "large", "last", "late",
        "laugh", "learn", "leave", "left", "let", "letter", "life", "light",
        "like", "line", "list", "little", "long", "look", "low", "made", "main",
        "make", "man", "many", "mark", "may", "me", "mean", "measure", "men",
        "might", "mile", "miss", "moon", "more", "most", "mother", "mountain",
        "move", "much", "multiply", "music", "must", "my", "name", "near", "need",
        "never", "new", "next", "night", "no", "north", "not", "nothing", "now",
        "numeral", "object", "of", "off", "often", "oil", "old", "on", "once",
        "one", "only", "open", "or", "order", "other", "oud", "our", "out", "over",
        "own", "page", "paint", "paper", "part", "pass", "picture", "piece",
        "place", "plain", "plane", "plant", "play", "please", "point", "port",
        "pose", "possible", "press", "problem", "product", "put", "question",
        "rain", "ran", "read", "ready", "real", "record", "red", "right", "river",
        "rock", "room", "round", "run", "said", "same", "saw", "say", "school",
        "sea", "second", "see", "seem", "self", "sentence", "set", "shape", "she",
        "ship", "short", "should", "show", "side", "since", "sit", "small", "snow",
        "so", "some", "song", "soon", "sorry", "sound", "south", "spell", "stand",
        "start", "state", "stay", "stead", "still", "story", "street", "study",
        "such", "sun", "sure", "surface", "system", "take", "talk", "tell", "test",
        "than", "thank", "that", "the", "their", "them", "then", "there", "these",
        "they", "think", "this", "those", "though", "thought", "thousand", "three",
        "through", "time", "tire", "to", "together", "told", "too", "took", "top",
        "tree", "try", "turn", "two", "under", "until", "up", "us", "use", "usual",
        "very", "walk", "want", "was", "watch", "water", "way", "we", "well",
        "went", "were", "what", "wheel", "when", "where", "which", "while",
        "white", "who", "whole", "why", "will", "wind", "with", "wonder", "wood",
        "word", "work", "world", "would", "year", "yes", "you", "young", "your",
    },
    builtin=True,
)

register_language(
    "fr", "Français",
    {
        "a": 7.64, "b": 0.90, "c": 3.26, "d": 3.67, "e": 14.72, "f": 1.07,
        "g": 0.87, "h": 0.74, "i": 7.53, "j": 0.55, "k": 0.05, "l": 5.46,
        "m": 2.97, "n": 7.10, "o": 5.80, "p": 3.02, "q": 1.36, "r": 6.55,
        "s": 7.95, "t": 7.24, "u": 6.31, "v": 1.63, "w": 0.11, "x": 0.39,
        "y": 0.13, "z": 0.14,
    },
    {
        "affaire", "aide", "air", "aller", "alors", "ame", "ami", "amie", "animal",
        "annee", "apres", "arbre", "argent", "arreter", "arriver", "art",
        "attendre", "au", "aucun", "aussi", "autre", "autres", "aux", "avait",
        "avant", "avec", "avion", "avoir", "basse", "bateau", "beaucoup", "bien",
        "boire", "bon", "bonjour", "bonne", "bruit", "campagne", "cas", "cause",
        "ce", "cela", "celui", "certain", "certains", "ces", "cet", "cette",
        "ceux", "chaise", "chaleur", "champ", "changer", "chaque", "chat",
        "chemin", "chercher", "chez", "chien", "chose", "ciel", "classe", "coeur",
        "comme", "commencer", "comment", "complexe", "continuer", "contre",
        "corps", "couleur", "courir", "culture", "dans", "de", "deja", "depuis",
        "dernier", "derniere", "des", "descendre", "different", "difficile",
        "dire", "donc", "donner", "dormir", "du", "eau", "ecole", "ecouter",
        "effet", "eleve", "elle", "en", "encore", "enfant", "ensemble", "entre",
        "entrer", "es", "esprit", "est", "et", "etait", "etes", "etre", "etude",
        "eux", "facile", "facon", "faire", "fait", "famille", "fausse", "faux",
        "femme", "fenetre", "fermer", "feu", "film", "finir", "fleur", "fois",
        "force", "foret", "forme", "fort", "forte", "frere", "froid", "fruit",
        "gagner", "garder", "general", "gens", "grand", "grande", "groupe", "haut",
        "heure", "histoire", "homme", "ici", "il", "ils", "image", "important",
        "impossible", "jamais", "jardin", "je", "jeu", "jeune", "jour", "la",
        "lac", "lait", "langue", "le", "legume", "les", "lettre", "leur", "livre",
        "local", "long", "longue", "lui", "lumiere", "lune", "main", "mais",
        "maison", "maitre", "manger", "maniere", "marcher", "matin", "mauvais",
        "me", "meme", "mer", "merci", "mere", "mes", "mettre", "minute", "moi",
        "mois", "moment", "mon", "monde", "montagne", "monter", "mot", "moyen",
        "musique", "national", "ne", "necessaire", "neige", "nom", "nombre", "non",
        "notre", "nous", "nouveau", "nouvelle", "nuit", "nul", "oeil", "oiseau",
        "ombre", "on", "ont", "orage", "ou", "oui", "ouvrir", "pain", "papier",
        "par", "pareil", "parent", "parler", "parole", "part", "particulier",
        "partie", "partir", "pas", "pays", "pendant", "perdre", "pere", "petit",
        "petite", "peu", "photo", "phrase", "pied", "place", "pluie", "plus",
        "plusieurs", "poisson", "pont", "porte", "porter", "possible", "pour",
        "pourquoi", "pouvoir", "premier", "premiere", "prendre", "prive",
        "probleme", "propre", "public", "quand", "que", "quel", "quelle",
        "quelque", "question", "qui", "raison", "regarder", "reponse", "rester",
        "rien", "riviere", "route", "rue", "salut", "sans", "savoir", "science",
        "se", "seconde", "semaine", "semblable", "ses", "seul", "seule", "si",
        "silence", "simple", "soeur", "soir", "soleil", "solution", "sommes",
        "son", "sont", "sortir", "sous", "special", "suis", "sur", "table", "te",
        "tel", "telle", "temps", "tenir", "terre", "tes", "test", "tete", "toi",
        "ton", "toujours", "tous", "tout", "toute", "toutes", "train", "travail",
        "tres", "trop", "trouver", "tu", "un", "une", "venir", "vent", "vers",
        "viande", "vie", "vieux", "village", "ville", "vin", "vitesse", "voir",
        "voiture", "voix", "votre", "vouloir", "vous", "vrai", "vraie",
    },
    builtin=True,
)

MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}
MORSE_REVERSE = {code: letter for letter, code in MORSE.items()}

# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

# Valid affine multipliers: those coprime with 26. Any other multiplier makes
# the cipher non-invertible — two different letters would map to the same
# result and even the recipient could not read it back.
AFFINE_KEYS = [a for a in range(1, 26) if math.gcd(a, 26) == 1]

MIN_RELIABLE_LENGTH = 40
MAX_VIGENERE_KEY_LENGTH = 20

# Plausibility score weights.
#
# Chi-squared weighs less than recognised words, for a specific reason: it can
# *reward* a bad decryption. Plaintext damaged at regular intervals — one wrong
# letter every twelve characters, which is what an almost-correct Vigenere key
# produces — sees its distribution drift towards the language average, so its
# chi-squared improves. Words, on the other hand, break. Without this balance a
# key wrong by a single letter scored better than the correct one.
CHI_WEIGHT = 0.30
WORD_WEIGHT = 0.50
COUNT_WEIGHT = 0.20

# Share of common words in natural text. Used as the reference point beyond
# which the signal is considered maximal. Saturating too early makes texts
# recognised at 56% and at 44% score identically, leaving chi-squared to decide
# alone — and it decides badly.
WORD_REFERENCE = 0.55

# Evidence weight beyond which recognition is considered complete.
#
# Expressed in `word_weight` units, that is cumulative "length − 1". A value of
# 25 corresponds to roughly eight ordinary four-letter words, or four long
# ones. Below that the score stays deliberately low, which is what stops a
# five-word text from claiming the same confidence as a fifty-word one.
WORD_EVIDENCE_REFERENCE = 25

# Length at which the letter distribution has converged.
#
# Below it, chi-squared is not *bad*: it is **unmeasurable**. Scoring an
# unmeasurable signal as a failed one costs a correct decryption most of that
# weight — on fifty letters chi-squared carries only 8% of what it could.
#
# The chi-squared weight therefore follows its own measurability, and the share
# it cannot carry goes to the **count of recognised words**, precisely the
# signal that says whether the vocabulary can be trusted. The weights still sum
# to 1: the score is not inflated, only reassigned to what is observable.
CHI_RELIABLE_LENGTH = 200

# Sentence punctuation. These marks pass through every classical cipher and
# teach nobody anything; reporting them would drown the useful warning. Any
# other symbol — @, $, #, %, / — does not belong to an ordinary sentence: it
# marks an address, a password or code, and its survival reveals the structure
# of the message even when the content stays hidden.
SENTENCE_MARKS = frozenset(".,;:!?'\"()[]{}«»…-–—")

# Score gap below which two settings are considered equivalent. Used to prefer
# the simplest one rather than whichever was tried first.
TIE_EPSILON = 0.02

# Index of coincidence expected from plaintext. Most European languages sit
# around 0.075; English is slightly lower than French.
PLAIN_IOC = 0.068

# Vigenere cracking thresholds.
MIN_COLUMN_LENGTH = 12        # below this, a column's index is noise
COLUMN_IOC_THRESHOLD = 0.058  # above this, a column looks like plaintext
MULTIPLE_IOC_MARGIN = 0.008   # gap required before preferring a multiple


# ---------------------------------------------------------------------------
# Scoring a plaintext candidate
# ---------------------------------------------------------------------------


def letters_only(text: str) -> str:
    """Keep only Latin letters, lowercased."""
    return "".join(c for c in text.lower() if c in ALPHABET)


def chi_squared(text: str, language: str) -> float:
    """
    Distance between observed letter frequencies and the language's own.

    The lower the value, the more the text resembles that language. Encrypted
    text typically scores very high, which is what separates a successful
    decryption from a failed one.
    """
    letters = letters_only(text)
    if not letters:
        return float("inf")

    expected_table = LANGUAGES[language].frequencies
    total = len(letters)
    score = 0.0

    for letter in ALPHABET:
        observed = letters.count(letter)
        expected = expected_table[letter] * total / 100
        if expected > 0:
            score += (observed - expected) ** 2 / expected

    return score / total


def transform_scope(before: str, after: str) -> dict:
    """
    What the transformation actually changed, and what it let through.

    Returns both sides on purpose. Reporting only what stayed intact forces the
    reader to derive the useful fact; stating "only the digits changed" answers
    the question directly.

    Symbols are not treated as one group, and that is the delicate part. A
    comma or a full stop is sentence punctuation: it passes through every
    classical cipher, nobody expects otherwise, and reporting it would be
    noise. An `@`, a `$` or a `#` is different — such marks do not occur in an
    ordinary sentence, they signal an address, a password or code. Their
    survival gives away no secret, but it gives away the **structure**: an
    intact `@` is enough to know one is looking at an email address.

    Comparison is positional, so it only means something when both texts have
    the same length. That holds for substitutions. In a transposition no
    character is "changed", only moved; in an encoding everything is replaced.
    In both cases the question does not apply and the function stays silent.
    """
    empty = {"changed": [], "untouched": []}
    if len(before) != len(after) or not before:
        return empty

    families = (
        ("letters", str.isalpha),
        ("digits", str.isdigit),
        ("symbols", lambda ch: not ch.isalnum() and not ch.isspace()
                    and ch not in SENTENCE_MARKS),
    )
    present, changed = set(), set()
    for source, result in zip(before, after):
        for name, belongs in families:
            if belongs(source):
                present.add(name)
                if source != result:
                    changed.add(name)

    if not present:
        return empty
    return {
        "changed": [n for n, _ in families if n in changed],
        "untouched": [n for n, _ in families if n in present and n not in changed],
    }


def tokenize(text: str) -> list:
    """
    Split the text into words, at real boundaries.

    `[a-z]+` stops at anything that is not a letter: space, comma, full stop,
    apostrophe, digit. So "the" followed by a comma is recognised as the word
    "the", while the "the" inside "other" is not. That is exactly the boundary
    required — substring matching would make half the dictionary match any
    gibberish.

    Single-letter tokens are discarded. An apostrophe splits "don't" into "don"
    and "t"; counting "t" as a miss would penalise a text that was in fact
    recognised. And a lone "a" appears in any scrambled text, making it false
    evidence.
    """
    return [w for w in re.findall(r"[a-z]+", text.lower()) if len(w) > 1]


def word_weight(word: str) -> int:
    """
    Evidence weight of a recognised word, growing with its length.

    Not all matches are worth the same, and the gap is not a matter of taste. A
    random two-letter string has one chance in 676 of forming a given word; a
    seven-letter string, one in eight billion. Finding "of" in a failed
    decryption is common; finding "because" is not.

    The weight used is `length − 1`. This is a deliberately simple
    approximation of the information actually carried, which is
    `L·log2(26) − log2(number of known words of that length)` — roughly 5 bits
    for two letters against 29 for seven. Their ratio, close to six, is what
    "length − 1" reproduces, without making the score depend on the exact
    composition of the loaded dictionary.
    """
    return len(word) - 1


def word_hits(text: str, language: str) -> tuple[float, int]:
    """
    Recognised common words: the **ratio** and the **evidence weight**.

    Both matter, for different reasons.

    The ratio says whether the text belongs to the language. It counts whole
    words without weighting: it measures coverage, and a long word the
    dictionary happens not to know must not weigh more than a short one it also
    does not know. Otherwise the score would punish gaps in the dictionary
    instead of judging the text.

    The weight says whether the ratio can be trusted. There length counts
    fully: three matches out of five and thirty out of fifty give the same
    ratio but not the same evidence — and "because" is not "of".
    """
    words = tokenize(text)
    if not words:
        return 0.0, 0
    known = LANGUAGES[language].words
    hits = [word for word in words if word in known]
    return len(hits) / len(words), sum(word_weight(word) for word in hits)


def index_of_coincidence(text: str) -> float:
    """
    Probability that two letters drawn at random are identical.

    Around 0.067 for plaintext, around 0.038 for random text. This is the tool
    that separates a **monoalphabetic** cipher — Caesar, Atbash, affine — from
    a **polyalphabetic** one such as Vigenere, without decrypting either: the
    first preserves the letter distribution, the second flattens it.
    """
    letters = letters_only(text)
    n = len(letters)
    if n < 2:
        return 0.0
    total = sum(letters.count(c) * (letters.count(c) - 1) for c in set(letters))
    return total / (n * (n - 1))


def plausibility(text: str) -> tuple[float, str]:
    """
    Plausibility score between 0 and 1, plus the most likely language.

    Three signals, each covering a weakness of the others:

    * **chi-squared** on letter frequencies — reliable on long text, silent on
      short text, and occasionally misleading (it can *reward* text damaged at
      regular intervals, whose distribution drifts towards the average);

    * **the ratio of recognised words** — decisive on short text, but blind to
      quantity: three matches out of five score like thirty out of fifty;

    * **the weight of recognised words** — this is what separates the two. Over
      five words coincidence remains possible. Over thirty, it does not.

    The score is computed across **every** registered language and the best one
    wins. Adding a language therefore extends both accuracy and detection.
    """
    best_score = 0.0
    best_language = next(iter(LANGUAGES))

    # Chi-squared weighs only as much as it can measure. On a text too short,
    # its share goes to the word count rather than being lost.
    measurable = min(len(letters_only(text)) / CHI_RELIABLE_LENGTH, 1.0)
    chi_weight = CHI_WEIGHT * measurable
    count_weight = COUNT_WEIGHT + (CHI_WEIGHT - chi_weight)

    for language in LANGUAGES:
        chi = chi_squared(text, language)
        ratio, evidence = word_hits(text, language)

        chi_term = math.exp(-chi / 0.6)
        ratio_term = min(ratio / WORD_REFERENCE, 1.0)
        count_term = min(evidence / WORD_EVIDENCE_REFERENCE, 1.0)

        score = (
            chi_weight * chi_term
            + WORD_WEIGHT * ratio_term
            + count_weight * count_term
        )

        if score > best_score:
            best_score = score
            best_language = language

    return best_score, best_language


# ---------------------------------------------------------------------------
# Substitution ciphers
# ---------------------------------------------------------------------------


def caesar(text: str, shift: int) -> str:
    """Alphabetic shift. Case and punctuation are preserved."""
    out = []
    for char in text:
        if char.isalpha() and char.lower() in ALPHABET:
            base = ord("A") if char.isupper() else ord("a")
            out.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            out.append(char)
    return "".join(out)


def atbash(text: str) -> str:
    """Mirrored alphabet: a<->z, b<->y. Its own inverse."""
    out = []
    for char in text:
        if char.isalpha() and char.lower() in ALPHABET:
            base = ord("A") if char.isupper() else ord("a")
            out.append(chr(base + 25 - (ord(char) - base)))
        else:
            out.append(char)
    return "".join(out)


def affine(text: str, a: int = 5, b: int = 8, decode: bool = False) -> str:
    """
    Affine cipher: E(x) = (a*x + b) mod 26.

    Generalises Caesar, which is only its a = 1 case. The multiplier must be
    coprime with 26, otherwise the transformation is not invertible and two
    distinct letters would collapse onto the same result.
    """
    if math.gcd(a, 26) != 1:
        raise ValueError(f"multiplier {a} is not invertible modulo 26")

    a_inverse = pow(a, -1, 26)
    out = []
    for char in text:
        if char.isalpha() and char.lower() in ALPHABET:
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            y = (a_inverse * (x - b)) % 26 if decode else (a * x + b) % 26
            out.append(chr(y + base))
        else:
            out.append(char)
    return "".join(out)


def rot5(text: str, shift: int = 5) -> str:
    """
    Rotation over the ten digits. Letters are left alone.

    Five is half of ten: as with every ROT, that choice makes the
    transformation its own inverse.
    """
    out = []
    for char in text:
        if char.isdigit():
            out.append(chr((ord(char) - ord("0") + shift) % 10 + ord("0")))
        else:
            out.append(char)
    return "".join(out)


def rot18(text: str) -> str:
    """
    ROT13 on letters and ROT5 on digits, applied together.

    Fills the gap left by ROT13 alone, which leaves numbers perfectly readable
    — a phone number passes straight through it.
    """
    return rot5(caesar(text, 13))


def rot47(text: str, shift: int = 47) -> str:
    """
    Rotation over the 94 printable ASCII characters, punctuation included.

    Unlike ROT13 it is not limited to letters: digits and symbols are
    transformed too. With the default shift of 47 it is its own inverse.
    """
    out = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            out.append(chr(33 + (code - 33 + shift) % 94))
        else:
            out.append(char)
    return "".join(out)


def vigenere(text: str, key: str, decode: bool = False, autokey: bool = False) -> str:
    """
    Variable shift driven by a key.

    In `autokey` mode the key is extended with the plaintext itself instead of
    being repeated. This is the variant Vigenere actually proposed, and it
    resists period analysis — Kasiski's method finds nothing, since no pattern
    repeats any more.
    """
    key_letters = letters_only(key)
    if not key_letters:
        return text

    out = []
    stream = list(key_letters)
    index = 0

    for char in text:
        if char.isalpha() and char.lower() in ALPHABET:
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(stream[index]) - ord("a")
            value = (ord(char) - base + (-shift if decode else shift)) % 26
            out.append(chr(value + base))

            if autokey:
                # The stream is extended with the plaintext letter: the
                # decrypted one when decoding, the original one when encoding.
                stream.append(chr(value + ord("a")) if decode else char.lower())
            elif index + 1 >= len(stream):
                stream.extend(key_letters)

            index += 1
        else:
            out.append(char)
    return "".join(out)


def beaufort(text: str, key: str) -> str:
    """
    Vigenere variant: E(x) = (key - text) mod 26.

    Its own inverse, which explains its use in mechanical machines — one
    setting served both to encipher and to decipher, so an operator could not
    get the direction wrong.
    """
    key_letters = letters_only(key)
    if not key_letters:
        return text

    out = []
    index = 0
    for char in text:
        if char.isalpha() and char.lower() in ALPHABET:
            base = ord("A") if char.isupper() else ord("a")
            k = ord(key_letters[index % len(key_letters)]) - ord("a")
            out.append(chr((k - (ord(char) - base)) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


# ---------------------------------------------------------------------------
# Transposition ciphers
# ---------------------------------------------------------------------------


def _rail_pattern(rails: int, length: int, offset: int = 0) -> list[int]:
    """
    Sequence of rails visited by the zigzag.

    `offset` moves the starting point within the cycle. Without it, only a
    fence begun on the first line going down can be read, which excludes half
    the variants met in practice.
    """
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    return [cycle[(i + offset) % len(cycle)] for i in range(length)]


def rail_fence(text: str, rails: int, decode: bool = False, offset: int = 0) -> str:
    """Write in a zigzag across N lines, then read line by line."""
    if rails < 2 or not text:
        return text

    positions = _rail_pattern(rails, len(text), offset)

    if not decode:
        rows = [""] * rails
        for char, rail in zip(text, positions):
            rows[rail] += char
        return "".join(rows)

    counts = [positions.count(r) for r in range(rails)]
    rows, cursor = [], 0
    for count in counts:
        rows.append(text[cursor:cursor + count])
        cursor += count

    indices = [0] * rails
    out = []
    for rail in positions:
        out.append(rows[rail][indices[rail]])
        indices[rail] += 1
    return "".join(out)


def columnar(text: str, key: str, decode: bool = False, pad: str = "x") -> str:
    """
    Columnar transposition.

    The text is written in rows beneath a key, then read column by column in
    the alphabetical order of the key's letters. Only that ordering matters:
    two keys with the same ranking give the same result.
    """
    key_letters = letters_only(key)
    if not key_letters:
        return text
    width = len(key_letters)
    order = sorted(range(width), key=lambda i: (key_letters[i], i))

    if not decode:
        padded = text + pad * ((-len(text)) % width)
        columns = ["".join(padded[i::width]) for i in range(width)]
        return "".join(columns[i] for i in order)

    height = len(text) // width
    columns: list[str] = [""] * width
    cursor = 0
    for i in order:
        columns[i] = text[cursor:cursor + height]
        cursor += height
    return "".join("".join(column[row] for column in columns) for row in range(height))


# ---------------------------------------------------------------------------
# Encodings
#
# These are not ciphers: there is no key and no secret. They are included
# because they routinely appear wrapped around real ciphers, and because a text
# that looks encrypted is often merely encoded.
# ---------------------------------------------------------------------------


def to_morse(text: str, letter_sep: str = " ", word_sep: str = " / ") -> str:
    """Separators vary between conventions, so they are configurable."""
    words = []
    for word in text.lower().split():
        codes = [MORSE[c] for c in word if c in MORSE]
        if codes:
            words.append(letter_sep.join(codes))
    return word_sep.join(words)


def from_morse(text: str, word_sep: str | None = None, letter_sep: str = " ") -> str:
    """
    Decode Morse, with separators either guessed or imposed.

    Without `word_sep`, reading is tolerant: `/`, `|` or a double space are all
    accepted, because no convention ever settled.

    With `word_sep`, the given separator is authoritative. This matters:
    `to_morse` accepts any separator, including a digit, so a decoder limited
    to three of them could produce text this same library could no longer read.
    **Every parameter accepted when encrypting must be accepted when
    decrypting**, otherwise the inverse is not one.
    """
    if word_sep:
        words = []
        for chunk in text.split(word_sep):
            codes = [c for c in (chunk.split(letter_sep) if letter_sep else chunk.split()) if c]
            if not codes:
                continue
            if any(code not in MORSE_REVERSE for code in codes):
                raise ValueError("invalid morse sequence")
            words.append("".join(MORSE_REVERSE[code] for code in codes))
        if not words:
            raise ValueError("invalid morse sequence")
        return " ".join(words).strip()

    normalised = text.replace("|", "/").replace("_", "-")
    normalised = re.sub(r"\s{2,}", " / ", normalised)

    out = []
    for token in normalised.replace("/", " / ").split():
        if token == "/":
            out.append(" ")
        elif token in MORSE_REVERSE:
            out.append(MORSE_REVERSE[token])
        else:
            raise ValueError("invalid morse sequence")
    return "".join(out).strip()


def to_hex(text: str, sep: str = "", prefix: str = "", upper: bool = False) -> str:
    values = [format(b, "02X" if upper else "02x") for b in text.encode("utf-8")]
    return sep.join(prefix + v for v in values)


def to_binary(text: str, sep: str = " ", bits: int = 8) -> str:
    return sep.join(format(b, f"0{bits}b") for b in text.encode("utf-8"))


def to_base64(text: str, urlsafe: bool = False) -> str:
    raw = text.encode("utf-8")
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(raw).decode("ascii")


def _decode_base64(text: str) -> str:
    cleaned = "".join(text.split())
    if len(cleaned) < 4:
        raise ValueError("trop court pour du base64")
    # The urlsafe variant replaces + and / with - and _; both alphabets are
    # accepted, and missing padding is restored since URLs often drop it.
    normalised = cleaned.replace("-", "+").replace("_", "/")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", normalised):
        raise ValueError("characters outside the base64 alphabet")
    normalised += "=" * ((-len(normalised)) % 4)
    return base64.b64decode(normalised).decode("utf-8")


def _printable(text: str) -> bool:
    """True when the text contains only readable characters."""
    return bool(text) and all(
        c in "\n\t" or 32 <= ord(c) < 127 or ord(c) > 160 for c in text
    )


def _decode_hex(text: str, sep: str | None = None, prefix: str | None = None) -> str:
    """
    Decode hexadecimal, with separator and prefix either guessed or imposed.

    With no settings, reading strips what occurs in practice: spaces, commas,
    colons, dashes and the `0x` prefix. When a separator or prefix is given,
    those are authoritative — `to_hex` accepts any of them, so the decoder must
    accept them too.
    """
    cleaned = text
    if prefix:
        cleaned = cleaned.replace(prefix, "")
    if sep:
        cleaned = cleaned.replace(sep, "")
    if not sep and not prefix:
        cleaned = re.sub(r"(0x|[\s,:;-])", "", cleaned, flags=re.IGNORECASE)
    else:
        cleaned = re.sub(r"\s", "", cleaned)
    if len(cleaned) < 4 or len(cleaned) % 2 != 0:
        raise ValueError("length incompatible with hexadecimal")
    decoded = binascii.unhexlify(cleaned).decode("utf-8")
    # A run of 0s and 1s is *also* valid hexadecimal. Without this check, a
    # continuous binary stream decodes into unreadable control bytes, and that
    # nonsense hypothesis competes with the correct one.
    if not _printable(decoded):
        raise ValueError("hexadecimal does not yield readable text")
    return decoded


def _decode_binary(text: str, bits: int | None = None, sep: str | None = None) -> str:
    """
    Decode a run of binary bytes, separated or not.

    Two forms occur in practice:

    * **separated** — `01000001 01110100`. Separators vary (space, comma, dash,
      pipe); accepting them all costs one character class.

    * **continuous** — `0100000101110100`, with no spaces at all. This is what
      any raw export produces. Rejecting it fails silently, because such a
      string is also valid hexadecimal: the hex decoder takes over and returns
      meaningless bytes with the confidence of a successful decode.

    `bits` forces the word width; without it, 8 is tried then 7, since
    seven-bit ASCII is still common in older formats. The width kept is the one
    that yields printable characters, since otherwise the split is arbitrary.
    """
    cleaned = text.strip()
    # An imposed separator is authoritative: `to_binary` accepts any of them,
    # including characters the default class does not cover.
    tokens = (
        [t for t in cleaned.split(sep) if t]
        if sep
        else re.split(r"[\s,;|-]+", cleaned)
    )

    if len(tokens) >= 2 and all(re.fullmatch(r"[01]{7,8}", t) for t in tokens):
        return "".join(chr(int(token, 2)) for token in tokens)

    stream = cleaned.replace(sep, "") if sep else re.sub(r"[\s,;|-]", "", cleaned)
    if len(stream) < 14 or not re.fullmatch(r"[01]+", stream):
        raise ValueError("ce ne sont pas des octets binaires")

    for width in ([int(bits)] if bits else [8, 7]):
        if len(stream) % width:
            continue
        chunks = [stream[i:i + width] for i in range(0, len(stream), width)]
        decoded = "".join(chr(int(chunk, 2)) for chunk in chunks)
        # A wrong width yields control characters. Rejecting them is the only
        # way to choose between 7 and 8 without knowing the source.
        if all(c == "\n" or c == "\t" or 32 <= ord(c) < 127 for c in decoded):
            return decoded

    raise ValueError("binary word width cannot be determined")


# ---------------------------------------------------------------------------
# Cryptanalysis
# ---------------------------------------------------------------------------


def _column_shift(column: str, language: str = "en") -> int:
    """Solve one column as a Caesar, by minimising chi-squared."""
    best_shift, best_score = 0, float("inf")
    for shift in range(26):
        decoded = "".join(
            chr((ord(c) - ord("a") - shift) % 26 + ord("a")) for c in column
        )
        score = chi_squared(decoded, language)
        if score < best_score:
            best_score, best_shift = score, shift
    return best_shift


def _column_beaufort(column: str, language: str = "en") -> int:
    """
    Solve one Beaufort-encrypted column.

    Beaufort defines `cipher = key - plain`, so `plain = key - cipher`. The
    search is the same as for Caesar, only the formula differs — but it does
    differ, and reusing the Vigenere one would yield a wrong key.
    """
    best_key, best_score = 0, float("inf")
    for k in range(26):
        decoded = "".join(
            chr((k - (ord(ch) - ord("a"))) % 26 + ord("a")) for ch in column
        )
        score = chi_squared(decoded, language)
        if score < best_score:
            best_score, best_key = score, k
    return best_key


def _key_length(letters: str, max_key_length: int) -> int | None:
    """
    Estimate the period of a polyalphabetic cipher.

    Shared by Vigenere and Beaufort: both split the text into columns of equal
    shift, and the index of coincidence rises at the correct length whatever
    formula is applied inside.
    """
    scores: dict[int, float] = {}
    for length in range(1, max_key_length + 1):
        if len(letters) // length < MIN_COLUMN_LENGTH:
            break
        columns = [letters[i::length] for i in range(length)]
        scores[length] = sum(index_of_coincidence(c) for c in columns) / length

    plausible = [length for length, ioc in scores.items() if ioc >= COLUMN_IOC_THRESHOLD]
    if not plausible:
        return None

    best_length = min(plausible)
    for multiple in range(2, max_key_length // best_length + 1):
        candidate = best_length * multiple
        if scores.get(candidate, 0) > scores[best_length] + MULTIPLE_IOC_MARGIN:
            best_length = candidate
    return best_length


def crack_beaufort(text: str, max_key_length: int = MAX_VIGENERE_KEY_LENGTH) -> tuple[str, str] | None:
    """Recover a Beaufort key without knowing it, as for Vigenere."""
    letters = letters_only(text)
    if len(letters) < 30:
        return None
    best_length = _key_length(letters, max_key_length)
    if best_length is None:
        return None

    language = "en" if chi_squared(letters, "en") < chi_squared(letters, "fr") else "fr"
    key = "".join(
        chr(_column_beaufort(letters[i::best_length], language) + ord("a"))
        for i in range(best_length)
    )
    return key, beaufort(text, key)


def crack_vigenere(text: str, max_key_length: int = MAX_VIGENERE_KEY_LENGTH) -> tuple[str, str] | None:
    """
    Recover the key without knowing it, and return `(key, plaintext)`.

    Two classical steps:

    1. **Key length.** For each candidate length the text is split into columns,
       one per key position. If the length is right, every column has undergone
       a single shift and therefore behaves like shifted plaintext: its index of
       coincidence rises towards 0.068. If the length is wrong, columns mix
       several shifts and the index stays near 0.038.

    2. **Key content.** Each column is then a plain Caesar, solved independently
       by minimising chi-squared.

    Returns `None` when the text is too short for the columns to be
    statistically usable — the threshold is low, but it exists.
    """
    letters = letters_only(text)
    if len(letters) < 30:
        return None

    # A column shorter than twelve letters carries no usable statistic: its
    # index of coincidence is noise, often high by accident. The smallest
    # credible length wins — any multiple of the true length scores comparably,
    # and taking the maximum would return the key repeated twice.
    best_length = _key_length(letters, max_key_length)
    if best_length is None:
        return None

    # The language is chosen once over the whole text rather than per column:
    # a single column is too short to decide.
    language = "en" if chi_squared(letters, "en") < chi_squared(letters, "fr") else "fr"
    key = "".join(
        chr(_column_shift(letters[i::best_length], language) + ord("a"))
        for i in range(best_length)
    )
    key = _refine_key(text, key)
    return key, vigenere(text, key, decode=True)


def _refine_key(text: str, key: str) -> str:
    """
    Fix mis-guessed key letters by judging the whole text.

    The chi-squared of a single column covers only a few dozen letters: enough
    to find most shifts, not all. One wrong letter is enough to make the
    plaintext unreadable every few characters.

    The fix re-judges each position against the **complete text** rather than
    its own column: recognised words decide where the letter distribution
    hesitated. Two passes suffice in practice, the second usually changing
    nothing.
    """
    current = list(key)
    for _ in range(2):
        changed = False
        for position in range(len(current)):
            best_letter = current[position]
            best_score, _ = plausibility(vigenere(text, "".join(current), decode=True))
            for letter in ALPHABET:
                if letter == current[position]:
                    continue
                trial = list(current)
                trial[position] = letter
                score, _ = plausibility(vigenere(text, "".join(trial), decode=True))
                if score > best_score:
                    best_score, best_letter = score, letter
            if best_letter != current[position]:
                current[position] = best_letter
                changed = True
        if not changed:
            break
    return "".join(current)


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------
#
# Messages aimed at the end user are **codes**, not sentences. A library that
# returns "Short sample" as prose imposes its language on every interface built
# on top of it. The code travels; the sentence is rendered at the last moment,
# by whoever knows which language to speak.
REASONS = {
    "empty": "No text provided.",
    "already_plain": (
        "This text is already readable: nothing suggests it is encrypted. "
        "The hypotheses below are kept for comparison only."
    ),
    "short_sample": (
        "Short sample ({length} letters). Statistical analysis is unreliable "
        "below {minimum} letters — the candidates below are indicative."
    ),
    "no_match": (
        "No convincing hypothesis. The text may use a method not covered here, "
        "or a key that could not be recovered."
    ),
    "ambiguous": (
        "Two hypotheses are too close to separate. A longer text would settle it."
    ),
    "polyalphabetic": (
        "The index of coincidence is low: the cipher is polyalphabetic. "
        "Vigenère with a short key is broken automatically; a long key, an "
        "autokey variant or a stream cipher is not."
    ),
}


@dataclass
class Variant:
    """
    One possible setting for a given cipher, with the text it produces.

    Variants exist because the best score is not always the right answer. On a
    short text two Caesar shifts can be separated by a hundredth of a point,
    and it is the reader, not the statistic, who recognises their own language.
    Hiding them means deciding on their behalf.
    """

    params: dict
    plaintext: str
    confidence: float

    def as_dict(self) -> dict:
        return {
            "params": self.params,
            "plaintext": self.plaintext[:VARIANT_PREVIEW],
            "confidence": round(self.confidence, 4),
        }


@dataclass
class Candidate:
    """One decryption hypothesis, with its score and its parameters."""

    cipher: str
    label: str
    plaintext: str
    confidence: float
    language: str
    detail: str = ""
    # Recovered parameters in reusable form: enough to replay the decryption
    # without running the search again.
    params: dict = field(default_factory=dict)
    # Other settings for the same cipher, most to least likely.
    variants: list["Variant"] = field(default_factory=list)
    # True when parameters were imposed by the caller rather than found by the
    # search. Interfaces should say so: an imposed result is not a discovery.
    pinned: bool = False
    # What this decryption changed and what it let through untouched.
    scope: dict = field(default_factory=lambda: {"changed": [], "untouched": []})

    def as_dict(self) -> dict:
        return {
            "cipher": self.cipher,
            "label": self.label,
            "plaintext": self.plaintext,
            "confidence": round(self.confidence, 4),
            "language": self.language,
            "detail": self.detail,
            "params": self.params,
            "pinned": self.pinned,
            "scope": self.scope,
            "variants": [v.as_dict() for v in self.variants],
        }


@dataclass
class Analysis:
    """The complete verdict."""

    candidates: list[Candidate] = field(default_factory=list)
    reliable: bool = True
    sample_length: int = 0
    index_of_coincidence: float = 0.0
    # Reason code and the data needed to fill it in. `note` renders it in
    # English, for command-line use.
    reason: str = ""
    reason_data: dict = field(default_factory=dict)
    polyalphabetic: bool = False
    # True when the submitted text is already readable. This is an answer in
    # its own right, not a failure: without it the engine "decrypts" plaintext
    # and announces an imaginary key with confidence.
    already_plain: bool = False

    @property
    def note(self) -> str:
        if not self.reason:
            return ""
        text = REASONS[self.reason].format(**self.reason_data)
        if self.polyalphabetic:
            text += " " + REASONS["polyalphabetic"]
        return text

    def as_dict(self) -> dict:
        return {
            "candidates": [c.as_dict() for c in self.candidates],
            "reliable": self.reliable,
            "sampleLength": self.sample_length,
            "indexOfCoincidence": round(self.index_of_coincidence, 4),
            "reason": self.reason,
            "reasonData": self.reason_data,
            "polyalphabetic": self.polyalphabetic,
            "note": self.note,
            "alreadyPlain": self.already_plain,
        }


# --- Analyse --------------------------------------------------------------

CIPHERS = (
    "base64", "hex", "binary", "morse", "reverse", "atbash",
    "caesar", "rot5", "rot18", "rot47", "affine", "railfence", "vigenere",
    "beaufort", "columnar",
)

# Key widths searched by default for columnar transposition.
#
# The cost is factorial: 120 permutations at width 5, 720 at width 6, 5040 at
# width 7. Measured over a full analysis that is roughly 250 ms, 500 ms and
# over two seconds respectively in a browser — enough for typing to stutter.
#
# The default therefore stops at five, which covers most keys met in practice.
# Beyond that the width stays a parameter: whoever wants it imposes it, and
# accepts the wait knowingly.
COLUMNAR_WIDTHS = list(range(2, 6))

# Number of alternative settings kept per cipher.
#
# Everything is returned. An arbitrarily truncated list is worse than none: it
# looks random and leaves the reader wondering whether the answer was among the
# ones hidden. Caesar has only 25 shifts, so showing a subset serves nobody.
#
# The ceiling now only bounds the unconstrained affine sweep, which produces
# 311 combinations.
MAX_VARIANTS = 400

# Variants are meant to be scanned, not read: an interface shows one line of
# each. Carrying 311 full texts would inflate the response with content nobody
# reads past the first few words.
VARIANT_PREVIEW = 220


def _pick(trials: list[tuple]) -> tuple:
    """
    Pick the best trial from a list **ordered simplest to most complex**.

    A replacement is only accepted when it is clearly better. At equal quality
    the simplest setting wins: it is the likeliest to be the original one, and
    the one a reader understands without explanation.
    """
    best = trials[0]
    for trial in trials[1:]:
        if trial[0] > best[0] + TIE_EPSILON:
            best = trial
    return best


def _variants_of(trials: list[tuple], chosen: tuple) -> list[Variant]:
    """The other settings, most to least likely, without duplicates."""
    ordered = sorted(trials, key=lambda t: -t[0])
    seen = {chosen[2].strip().lower()}
    out: list[Variant] = []
    for score, params, plaintext, _language in ordered:
        signature = plaintext.strip().lower()
        if signature in seen:
            continue
        seen.add(signature)
        out.append(Variant(params, plaintext, score))
        if len(out) >= MAX_VARIANTS:
            break
    return out


def analyse(
    text: str,
    only: list[str] | None = None,
    params: dict | None = None,
) -> Analysis:
    """
    Try every cipher and rank the results.

    `only` narrows the search when the caller already knows the cipher family.
    Ranking is unchanged; it simply covers fewer candidates.

    `params` imposes settings instead of searching for them::

        analyse(text, ["caesar"], {"caesar": {"shift": 3}})

    An imposed parameter is not explored, and the returned candidate carries
    `pinned=True` so the caller knows the result was dictated rather than
    discovered. That is the difference between "the engine believes this is a
    Caesar of 3" and "here is what a Caesar of 3 produces".
    """
    raw = text
    text = text.strip()
    pinned = params or {}
    result = Analysis(
        sample_length=len(letters_only(text)),
        index_of_coincidence=index_of_coincidence(text),
    )

    if not text:
        result.reliable = False
        result.reason = "empty"
        return result

    def wanted(name: str) -> bool:
        return only is None or name in only

    def chosen(name: str, key: str, default: list, cast=int) -> tuple[list, bool]:
        """
        Values to explore for one parameter, and whether it was imposed.

        A parameter may be pinned to **one** value or to **several**: "try
        shifts 3, 7 and 13" is a legitimate request, and more useful than a
        single choice when hesitating. A lone value is therefore treated as a
        one-element list, so callers need not know the difference.
        """
        given = (pinned.get(name) or {}).get(key)
        if given in (None, "", []):
            return default, False
        values = given if isinstance(given, (list, tuple)) else [given]
        return [cast(v) for v in values], True

    candidates: list[Candidate] = []

    # Encodings either decode cleanly or fail. There is no middle ground, so
    # their confidence depends only on the text obtained.
    if wanted("base64"):
        try:
            decoded = _decode_base64(text)
            if decoded.strip():
                score, language = plausibility(decoded)
                candidates.append(
                    Candidate("base64", "Base64", decoded, min(score + 0.25, 1.0),
                              language, "Structurally valid decoding")
                )
        except Exception:
            pass

    if wanted("hex"):
        seps, sep_pin = chosen("hex", "sep", [None], cast=str)
        prefixes, pre_pin = chosen("hex", "prefix", [None], cast=str)
        try:
            decoded = _decode_hex(text, seps[0], prefixes[0])
            if decoded.strip():
                score, language = plausibility(decoded)
                params_ = {k: v for k, v in
                           (("sep", seps[0]), ("prefix", prefixes[0])) if v}
                candidates.append(
                    Candidate("hex", "Hexadecimal", decoded, min(score + 0.25, 1.0),
                              language, "Structurally valid decoding", params_,
                              pinned=sep_pin or pre_pin)
                )
        except Exception:
            pass

    if wanted("morse"):
        word_seps, word_pin = chosen("morse", "word_sep", [None], cast=str)
        letter_seps, letter_pin = chosen("morse", "letter_sep", [" "], cast=str)
        try:
            decoded = from_morse(text, word_seps[0], letter_seps[0])
            if decoded.strip():
                score, language = plausibility(decoded)
                params_ = {k: v for k, v in
                           (("word_sep", word_seps[0]),
                            ("letter_sep", letter_seps[0] if letter_pin else None))
                           if v}
                candidates.append(
                    Candidate("morse", "Morse", decoded, min(score + 0.25, 1.0),
                              language, "Structurally valid decoding", params_,
                              pinned=word_pin or letter_pin)
                )
        except Exception:
            pass

    # Binary is handled separately: it is the only encoding whose reading
    # depends on a setting, the word width. On a separated stream the width is
    # read from the tokens; on a continuous one it must be guessed or imposed.
    if wanted("binary"):
        widths, was_pinned = chosen("binary", "bits", [8, 7])
        bin_seps, sep_pinned = chosen("binary", "sep", [None], cast=str)
        trials = []
        for width in widths:
            try:
                decoded = _decode_binary(text, width, bin_seps[0])
            except Exception:
                continue
            if not decoded.strip():
                continue
            score, language = plausibility(decoded)
            trials.append((min(score + 0.25, 1.0), {"bits": width}, decoded, language))
        if trials:
            score, params_, decoded, language = _pick(trials)
            if bin_seps[0]:
                params_ = dict(params_, sep=bin_seps[0])
            candidates.append(
                Candidate("binary", "Binary", decoded, score, language,
                          f"{params_['bits']} bits", params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=was_pinned or sep_pinned)
            )

    if wanted("reverse"):
        reversed_text = text[::-1]
        score, language = plausibility(reversed_text)
        candidates.append(Candidate("reverse", "Reversed text", reversed_text,
                                    score, language))

    if wanted("atbash"):
        decoded = atbash(text)
        score, language = plausibility(decoded)
        candidates.append(Candidate("atbash", "Atbash", decoded, score, language))

    if wanted("rot47"):
        # ROT47 is not swept. An arbitrary ASCII shift is not a named cipher:
        # it is a Caesar widened to punctuation, and sweeping it duplicates the
        # Caesar results in the ranking. Only 47 is canonical — the value that
        # makes the transformation its own inverse. A caller can still impose
        # another shift to explore.
        shifts, was_pinned = chosen("rot47", "shift", [47])
        trials = []
        for shift in shifts:
            decoded = rot47(text, -shift)
            score, language = plausibility(decoded)
            trials.append((score, {"shift": shift}, decoded, language))
        score, params_, decoded, language = _pick(trials)
        candidates.append(
            Candidate("rot47", "ROT47", decoded, score, language,
                      f"shift {params_['shift']}", params_,
                      _variants_of(trials, (score, params_, decoded, language)),
                      pinned=was_pinned)
        )

    if wanted("caesar"):
        shifts, was_pinned = chosen("caesar", "shift", list(range(1, 26)))
        trials = []
        for shift in shifts:
            decoded = caesar(text, -shift)
            score, language = plausibility(decoded)
            trials.append((score, {"shift": shift}, decoded, language))
        score, params_, decoded, language = _pick(trials)
        label = "ROT13" if params_["shift"] == 13 else "Caesar"
        candidates.append(
            Candidate("caesar", label, decoded, score, language,
                      f"shift {params_['shift']}", params_,
                      _variants_of(trials, (score, params_, decoded, language)),
                      pinned=was_pinned)
        )

    # The ROT family: same idea, different alphabets. None takes a parameter,
    # since the shift is part of the name.
    for name, label, transform in (("rot5", "ROT5", rot5), ("rot18", "ROT18", rot18)):
        if not wanted(name):
            continue
        decoded = transform(text)
        score, language = plausibility(decoded)
        candidates.append(Candidate(name, label, decoded, score, language))

    if wanted("affine"):
        # a = 1 is a Caesar: already covered, and the duplicate would pollute
        # the ranking with two identical entries.
        a_values, a_pinned = chosen("affine", "a", [a for a in AFFINE_KEYS if a != 1])
        b_values, b_pinned = chosen("affine", "b", list(range(26)))
        trials = []
        for a in a_values:
            if math.gcd(a, 26) != 1:
                continue
            for b in b_values:
                decoded = affine(text, a, b, decode=True)
                score, language = plausibility(decoded)
                trials.append((score, {"a": a, "b": b}, decoded, language))
        if trials:
            score, params_, decoded, language = _pick(trials)
            candidates.append(
                Candidate("affine", "Affine", decoded, score, language,
                          f"a={params_['a']}, b={params_['b']}", params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=a_pinned or b_pinned)
            )

    if wanted("railfence"):
        # Rail fence parameters are not uniquely identifiable: for a given
        # rail count several offsets produce nearly the same text, and the best
        # score is not always the original offset. The sweep therefore runs
        # simplest to most complex and only accepts a replacement that is
        # *clearly* better.
        #
        # Both forms of the text are tried. Transposition is position
        # sensitive: stripping a leading space shifts the whole pattern and
        # makes decryption impossible, yet pasted text often carries one.
        rail_values, rails_pinned = chosen("railfence", "rails", list(range(2, 8)))
        trials = []
        sources = [raw] if raw == text else [text, raw]
        for source in sources:
            for rails in rail_values:
                if rails < 2:
                    continue
                offsets, offset_pinned = chosen(
                    "railfence", "offset", list(range(2 * rails - 2))
                )
                for offset in offsets:
                    decoded = rail_fence(source, rails, decode=True, offset=offset)
                    score, language = plausibility(decoded)
                    trials.append((score, {"rails": rails, "offset": offset},
                                   decoded, language))
        _, offset_pinned = chosen("railfence", "offset", [])
        if trials:
            score, params_, decoded, language = _pick(trials)
            detail = f"{params_['rails']} rails"
            if params_["offset"]:
                detail += f", offset {params_['offset']}"
            candidates.append(
                Candidate("railfence", "Rail fence", decoded, score, language,
                          detail, params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=rails_pinned or offset_pinned)
            )

    # Vigenere requires real cryptanalysis: the key is reconstructed, not
    # brute-forced.
    if wanted("vigenere"):
        keys, was_pinned = chosen("vigenere", "key", [], cast=str)
        autokeys, auto_pinned = chosen("vigenere", "autokey", [False], cast=bool)
        if was_pinned:
            trials = []
            for key in keys:
                for auto in autokeys:
                    decoded = vigenere(text, key, decode=True, autokey=auto)
                    score, language = plausibility(decoded)
                    params_ = {"key": key}
                    if auto:
                        params_["autokey"] = True
                    trials.append((score, params_, decoded, language))
            score, params_, decoded, language = _pick(trials)
            candidates.append(
                Candidate("vigenere", "Vigenère", decoded, score, language,
                          f"key \"{params_['key']}\"", params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=True)
            )
        else:
            cracked = crack_vigenere(text)
            if cracked:
                key, decoded = cracked
                score, language = plausibility(decoded)
                candidates.append(
                    Candidate("vigenere", "Vigenère", decoded, score, language,
                              f"recovered key \"{key}\"", {"key": key})
                )

    # Beaufort: same cryptanalysis as Vigenere, different formula. Its key can
    # therefore be recovered without knowing it.
    if wanted("beaufort"):
        keys, was_pinned = chosen("beaufort", "key", [], cast=str)
        if was_pinned:
            trials = []
            for key in keys:
                decoded = beaufort(text, key)
                score, language = plausibility(decoded)
                trials.append((score, {"key": key}, decoded, language))
            score, params_, decoded, language = _pick(trials)
            candidates.append(
                Candidate("beaufort", "Beaufort", decoded, score, language,
                          f"key \"{params_['key']}\"", params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=True)
            )
        else:
            cracked = crack_beaufort(text)
            if cracked:
                key, decoded = cracked
                score, language = plausibility(decoded)
                candidates.append(
                    Candidate("beaufort", "Beaufort", decoded, score, language,
                              f"recovered key \"{key}\"", {"key": key})
                )

    # Columnar transposition. Without a key the permutations are enumerated:
    # only the key's alphabetical ordering matters, not its letters, so one
    # representative key per permutation covers every possible key of that
    # width.
    if wanted("columnar"):
        keys, key_pinned = chosen("columnar", "key", [], cast=str)
        widths, width_pinned = chosen("columnar", "width", COLUMNAR_WIDTHS)
        trials = []
        # Both forms of the text, exactly as for the rail fence: transposition
        # is position sensitive, and the ciphertext often ends with padding
        # whitespace. Stripping it shifts the whole grid and makes an otherwise
        # intact text unreadable.
        sources = [raw] if raw == text else [text, raw]
        if key_pinned:
            for source in sources:
                for key in keys:
                    decoded = columnar(source, key, decode=True)
                    score, language = plausibility(decoded)
                    trials.append((score, {"key": key}, decoded, language))
        else:
            for source in sources:
                for width in widths:
                    if width < 2 or len(letters_only(source)) < width * 2:
                        continue
                    for order in itertools.permutations(range(width)):
                        key = "".join(chr(ord("a") + order.index(i)) for i in range(width))
                        decoded = columnar(source, key, decode=True)
                        score, language = plausibility(decoded)
                        trials.append((score, {"key": key, "width": width}, decoded, language))
        if trials:
            score, params_, decoded, language = _pick(trials)
            candidates.append(
                Candidate("columnar", "Columnar", decoded, score, language,
                          f"key \"{params_['key']}\"", params_,
                          _variants_of(trials, (score, params_, decoded, language)),
                          pinned=key_pinned or width_pinned)
            )

    for candidate in candidates:
        candidate.scope = transform_scope(text, candidate.plaintext)

    candidates.sort(key=lambda c: c.confidence, reverse=True)

    # Some families overlap: Atbash is affine a=25 b=25, Caesar is affine a=1,
    # ROT13 is Caesar 13. Without deduplication the engine shows the same
    # plaintext twice and then reports "ambiguous", when there was only ever
    # one hypothesis.
    #
    # The sort is stable, so at equal confidence the entry kept is the one
    # inserted first. Ciphers are added most specific to most general, which
    # means "Atbash" wins over "affine a=25 b=25" — the name a reader expects.
    #
    # A candidate that returns the submitted text has decrypted nothing: it is
    # a disguised identity, such as Vigenere with the key "a". Presenting it as
    # a result would be a polite lie. An **imposed** setting escapes the rule:
    # the caller asked to see what it produces, even if the answer is nothing.
    seen: set[str] = {text.strip().lower()}
    unique: list[Candidate] = []
    for candidate in candidates:
        signature = candidate.plaintext.strip().lower()
        if signature in seen and not candidate.pinned:
            continue
        seen.add(signature)
        unique.append(candidate)

    candidates = unique

    # The verdict is judged on the **best** candidate, before any display
    # reordering: it is a measurement and must not depend on presentation.
    scored = list(candidates)

    # An imposed setting comes first whatever its score. It is a request, not
    # a competing hypothesis: the caller supplied a key and wants to see the
    # result. On text encrypted in several layers, removing the right layer
    # leaves something still unreadable and therefore badly scored, which would
    # bury the exact answer under a meaningless hypothesis.
    candidates.sort(key=lambda c: (not c.pinned, -c.confidence))
    result.candidates = candidates

    # --- Verdict honesty ---------------------------------------------------

    # The length that matters is that of the **resulting text**, not of the
    # ciphertext. A Morse message contains no letters at all: measuring the
    # input would declare an exact decoding "insufficient sample".
    evidence_length = (
        len(letters_only(scored[0].plaintext)) if scored else result.sample_length
    )

    # Is the submitted text already readable? The question must be asked
    # first, otherwise the engine searches for a key on a message that has
    # none, and always ends up finding one.
    source_score, _ = plausibility(text)
    if source_score >= 0.45 and result.sample_length >= MIN_RELIABLE_LENGTH:
        result.already_plain = True
        result.reliable = True
        result.reason = "already_plain"
        return result

    if evidence_length < MIN_RELIABLE_LENGTH:
        result.reliable = False
        result.reason = "short_sample"
        result.reason_data = {"length": evidence_length, "minimum": MIN_RELIABLE_LENGTH}
    elif not scored or scored[0].confidence < 0.35:
        result.reliable = False
        result.reason = "no_match"
    elif len(scored) > 1 and scored[0].confidence - scored[1].confidence < 0.08:
        result.reliable = False
        result.reason = "ambiguous"

    if (
        evidence_length >= MIN_RELIABLE_LENGTH
        and (not scored or scored[0].confidence < 0.5)
        and result.index_of_coincidence < 0.05
    ):
        result.polyalphabetic = True

    return result


# ---------------------------------------------------------------------------
# Public encryption API
# ---------------------------------------------------------------------------


def encode(text: str, cipher: str, **params) -> str:
    """
    Encrypt. Each method accepts its own keyword parameters::

        encode(t, "caesar", shift=7)
        encode(t, "affine", a=5, b=8)
        encode(t, "railfence", rails=4, offset=2)
        encode(t, "vigenere", key="disyner", autokey=True)
        encode(t, "hex", sep=" ", prefix="0x", upper=True)
        encode(t, "base64", urlsafe=True)
    """
    if cipher == "caesar":
        return caesar(text, params.get("shift", 3))
    if cipher == "rot13":
        return caesar(text, 13)
    if cipher == "rot5":
        return rot5(text)
    if cipher == "rot18":
        return rot18(text)
    if cipher == "rot47":
        return rot47(text, params.get("shift", 47))
    if cipher == "atbash":
        return atbash(text)
    if cipher == "affine":
        return affine(text, params.get("a", 5), params.get("b", 8))
    if cipher == "vigenere":
        return vigenere(text, params.get("key", ""), autokey=params.get("autokey", False))
    if cipher == "beaufort":
        return beaufort(text, params.get("key", ""))
    if cipher == "reverse":
        return text[::-1]
    if cipher == "railfence":
        return rail_fence(text, params.get("rails", 3), offset=params.get("offset", 0))
    if cipher == "columnar":
        return columnar(text, params.get("key", ""), pad=params.get("pad", "x"))
    if cipher == "base64":
        return to_base64(text, params.get("urlsafe", False))
    if cipher == "hex":
        return to_hex(text, params.get("sep", ""), params.get("prefix", ""),
                      params.get("upper", False))
    if cipher == "binary":
        return to_binary(text, params.get("sep", " "), params.get("bits", 8))
    if cipher == "morse":
        return to_morse(text, params.get("letter_sep", " "), params.get("word_sep", " / "))
    raise ValueError(f"unknown cipher: {cipher}")


def round_trip_loss(text: str, cipher: str, params=None) -> list:
    """
    What the cipher **destroys** for good, as opposed to what it lets through.

    Two very different faults are easily confused. A character that passes
    through intact reveals structure: that is a leak, but the text is whole. A
    **deleted** character is gone for good — the recipient receives a truncated
    message, and no key will bring it back.

    Morse is the only case here, and it is silent about it: any mark absent
    from its table is dropped, so commas, at-signs and dashes vanish without a
    word. Capitals too.

    The measurement is a round trip: encrypt, decrypt, compare with the
    original. That is the only method valid across every cipher at once —
    comparing input and output directly is meaningless when they do not share
    an alphabet. It will still hold for a cipher added later, with no extra
    work.
    """
    params = params or {}
    try:
        restored = decode_with_key(encode(text, cipher, **params), cipher, **params)
    except Exception:
        return []

    families = (
        ("letters", str.isalpha),
        ("digits", str.isdigit),
        ("punctuation", lambda ch: ch in SENTENCE_MARKS),
        ("symbols", lambda ch: not ch.isalnum() and not ch.isspace()
                    and ch not in SENTENCE_MARKS),
    )
    lost = [
        name
        for name, belongs in families
        if sum(1 for ch in text if belongs(ch))
        > sum(1 for ch in restored if belongs(ch))
    ]
    # Case is not a character family: it is lost without a single mark
    # disappearing. It still deserves reporting, since it does not come back
    # either.
    if any(ch.isupper() for ch in text) and not any(ch.isupper() for ch in restored):
        lost.append("case")
    return lost


def encode_stages(text: str, steps) -> list:
    """
    Encrypt through a chain and return **every stage**, not just the result.

    `steps` is a sequence of `{"cipher": name, "params": {...}}`, applied in
    the given order::

        encode_stages(t, [
            {"cipher": "caesar", "params": {"shift": 7}},
            {"cipher": "reverse"},
            {"cipher": "base64"},
        ])

    Returning intermediate states rather than only the final output is not a
    luxury: without them a chain that produces an unexpected result is a black
    box, and there is no way to tell which step went wrong.

    Two caveats are worth knowing, because order is not neutral:

    * some ciphers **lose information**. Morse keeps neither case nor
      punctuation, so whatever runs after it will never get them back;

    * substitution ciphers act on letters only. Placing a Caesar **after** a
      Morse or binary step does nothing at all — there is no letter left to
      shift. The chain stays valid, but the step is useless, and seeing it in
      the intermediate states shows that immediately.
    """
    stages = []
    current = text
    for step in steps:
        previous = current
        current = encode(current, step["cipher"], **(step.get("params") or {}))
        stages.append({"cipher": step["cipher"],
                       "params": step.get("params") or {},
                       "output": current,
                       "scope": transform_scope(previous, current),
                       "lost": round_trip_loss(previous, step["cipher"],
                                               step.get("params"))})
    return stages


def encode_pipeline(text: str, steps) -> str:
    """Encrypt through a chain and return only the final result."""
    stages = encode_stages(text, steps)
    return stages[-1]["output"] if stages else text


def decode_pipeline(text: str, steps) -> str:
    """
    Decrypt a chain by walking the steps **backwards**.

    That is the only correct reading: the last transformation applied is the
    first to undo. Passing the same list used for encryption is therefore
    enough, with no need to reverse it by hand — an inversion left to the
    caller is a mistake that eventually happens.
    """
    for step in reversed(list(steps)):
        text = decode_with_key(text, step["cipher"], **(step.get("params") or {}))
    return text


def decode_with_key(text: str, cipher: str, **params) -> str:
    """Decrypt when the method and its parameters are known."""
    if cipher == "caesar":
        return caesar(text, -params.get("shift", 3))
    if cipher == "rot13":
        return caesar(text, 13)
    if cipher == "rot5":
        return rot5(text, -5)
    if cipher == "rot18":
        return rot18(text)
    if cipher == "rot47":
        return rot47(text, -params.get("shift", 47))
    if cipher == "atbash":
        return atbash(text)
    if cipher == "affine":
        return affine(text, params.get("a", 5), params.get("b", 8), decode=True)
    if cipher == "vigenere":
        return vigenere(text, params.get("key", ""), decode=True,
                        autokey=params.get("autokey", False))
    if cipher == "beaufort":
        return beaufort(text, params.get("key", ""))
    if cipher == "reverse":
        return text[::-1]
    if cipher == "railfence":
        return rail_fence(text, params.get("rails", 3), decode=True,
                          offset=params.get("offset", 0))
    if cipher == "columnar":
        return columnar(text, params.get("key", ""), decode=True)
    if cipher == "base64":
        return _decode_base64(text)
    if cipher == "hex":
        return _decode_hex(text)
    if cipher == "binary":
        return _decode_binary(text)
    if cipher == "morse":
        return from_morse(text)
    raise ValueError(f"unknown cipher: {cipher}")


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------

def _cli(argv=None) -> int:
    """Command-line entry point: analyse a text and print the report as JSON."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print('usage: disypher "encrypted text"', file=sys.stderr)
        return 1
    report = analyse(" ".join(args))
    try:
        print(_json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
    except BrokenPipeError:
        # `disypher text | head` closes the pipe early. Python would report
        # this as a crash on exit; the shell considers it perfectly normal.
        import os

        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
