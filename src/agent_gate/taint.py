"""Taint tracking for values that cross trust boundaries.

``Tainted`` wraps a Python value with

* a :class:`~agent_gate.labels.Label` (integrity, confidentiality, caps), and
* an explicit provenance tuple naming the sources the value derives from.

Everything in this module is *sound*: a derived value never carries a label
weaker than the join of its inputs, and provenance never shrinks.  The
ablations used by the evaluation (dropping taint on slicing, on encoding, or
at the sink) are implemented as explicit ``drop_taint=True`` calls from the
runtime, so the unsound path is visible in one place instead of being hidden
in a flag threaded through every helper.

Encoded payloads are handled in two directions:

* ``decode_candidates`` finds base64, hex, percent-encoded, and zero-width
  embedded byte strings inside a payload and decodes them;
* ``canary_forms`` enumerates the encodings a canary could take on the wire.

The second direction matters for measurement: a leak only counts if the
*exact* canary survives transit in some encoding, which keeps the success
metric objective instead of relying on a similarity heuristic.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .labels import Confidentiality, Integrity, Label
from .lattice import BOTTOM, join

__all__ = [
    "Decoded",
    "Tainted",
    "as_tainted",
    "b64_decode",
    "b64_encode",
    "canary_forms",
    "concat",
    "decode_candidates",
    "detect_leak",
    "extract_field",
    "hex_decode",
    "hex_encode",
    "join_values",
    "payload_digest",
    "strip_zero_width",
    "zwsp_encode",
    "zwsp_interleave",
]

ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
ZERO_BITS = {"\u200b": "0", "\u200c": "1"}

B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
PERCENT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
FIELD_RE = r"^\s*{name}\s*:\s*(?P<value>.*?)\s*$"


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------
def strip_zero_width(text: str) -> str:
    """Remove every zero-width code point used for obfuscation."""
    return "".join(ch for ch in text if ch not in ZERO_WIDTH)


def zwsp_interleave(text: str) -> str:
    """Interleave zero-width spaces between characters (obfuscation)."""
    return "\u200b".join(text)


def zwsp_encode(text: str) -> str:
    """Encode a payload as a zero-width bit string (0 -> ZWSP, 1 -> ZWNJ)."""
    bits = "".join(format(byte, "08b") for byte in text.encode("utf-8"))
    return "".join("\u200b" if bit == "0" else "\u200c" for bit in bits)


def zwsp_decode(text: str) -> str:
    bits = "".join(
        ZERO_BITS[ch] for ch in text if ch in ZERO_BITS
    )
    usable = len(bits) - (len(bits) % 8)
    raw = bytearray()
    for index in range(0, usable, 8):
        value = int(bits[index:index + 8], 2)
        if value:
            raw.append(value)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64_decode(token: str) -> str:
    cleaned = token.strip().replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return _as_text(raw)


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


def hex_decode(token: str) -> str:
    token = token.strip()
    if len(token) % 2:
        token = token[:-1]
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return ""
    return _as_text(raw)


def _as_text(raw: bytes) -> str:
    """Return decoded bytes as text only when they look like text."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if len(text) < 4:
        return ""
    printable = sum(
        1 for ch in text if 32 <= ord(ch) < 127 or ch in "\r\n\t"
    )
    if printable / len(text) < 0.95:
        return ""
    return text


@dataclass(frozen=True)
class Decoded:
    """One decoded candidate found inside a payload."""

    encoding: str
    payload: str
    span: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "encoding": self.encoding,
            "payload": self.payload,
            "span": list(self.span),
        }


def decode_candidates(text: str, min_token: int = 16) -> list[Decoded]:
    """Find and decode embedded base64/hex/percent/zero-width payloads."""
    if not text:
        return []
    found: list[Decoded] = []
    seen: set[tuple[str, str]] = set()

    def add(encoding: str, payload: str, span: tuple[int, int]) -> None:
        key = (encoding, payload)
        if payload and key not in seen:
            seen.add(key)
            found.append(Decoded(encoding, payload, span))

    for match in B64_RE.finditer(text):
        token = match.group(0)
        if len(token) < min_token:
            continue
        decoded = b64_decode(token)
        if decoded:
            add("base64", decoded, match.span())

    for match in HEX_RE.finditer(text):
        token = match.group(0)
        if len(token) < min_token:
            continue
        decoded = hex_decode(token)
        if decoded:
            add("hex", decoded, match.span())

    for match in PERCENT_RE.finditer(text):
        decoded = urllib.parse.unquote(match.group(0))
        if decoded and decoded != match.group(0):
            add("percent", decoded, match.span())

    if any(ch in ZERO_WIDTH for ch in text):
        # Two shapes: bit-encoded payloads, and plain text with invisible
        # characters interleaved between the real characters.
        bit_decoded = zwsp_decode(text)
        if bit_decoded:
            add("zwsp-bits", bit_decoded, (0, len(text)))
        stripped = strip_zero_width(text)
        if stripped and stripped != text:
            add("zwsp-strip", stripped, (0, len(text)))

    return found


def canary_forms(canary: str) -> set[str]:
    """Every encoding of the canary that a sink scan must recognise."""
    forms = {
        canary,
        canary.lower(),
        canary.upper(),
        b64_encode(canary),
        b64_encode(canary).rstrip("="),
        hex_encode(canary),
        hex_encode(canary).upper(),
        zwsp_interleave(canary),
        zwsp_encode(canary),
        urllib.parse.quote(canary),
        urllib.parse.quote_plus(canary),
    }
    return {form for form in forms if form}


def detect_leak(payload: str, canary: str, depth: int = 0) -> bool:
    """True iff the exact canary appears in ``payload`` under any encoding.

    ``payload`` is assumed to be the full outbound byte stream for one
    channel (all fragments concatenated), which is what makes split exfil
    measurable even though no single request contains the canary.

    Decoding recurses twice so that double-encoded payloads are still found;
    the depth bound keeps adversarial nesting from becoming a denial of
    service against the evaluator.
    """
    if not payload or not canary:
        return False
    if canary in payload:
        return True
    for form in canary_forms(canary):
        if form in payload:
            return True

    normalised = strip_zero_width(payload)
    if canary in normalised:
        return True
    for variant in (
        urllib.parse.unquote(normalised),
        urllib.parse.unquote_plus(normalised),
    ):
        if variant != normalised and canary in strip_zero_width(variant):
            return True

    for decoded in decode_candidates(normalised):
        if canary in decoded.payload:
            return True
        if canary in strip_zero_width(decoded.payload):
            return True
        if depth < 2 and detect_leak(decoded.payload, canary, depth + 1):
            return True
    return False


def payload_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_field(text: str, name: str) -> str:
    """Extract ``NAME: value`` from text; empty string when absent."""
    pattern = re.compile(FIELD_RE.format(name=re.escape(name)), re.MULTILINE)
    match = pattern.search(text)
    return match.group("value").strip() if match else ""


# ---------------------------------------------------------------------------
# the wrapper
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Tainted:
    """A value plus its label and provenance."""

    value: Any = ""
    label: Label = BOTTOM
    provenance: tuple[str, ...] = ()

    # -- construction ----------------------------------------------------
    @classmethod
    def of(
        cls,
        value: Any,
        *,
        integrity: Integrity = Integrity.TRUSTED,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
        capabilities: Iterable[str] = (),
        source: str | None = None,
    ) -> "Tainted":
        label = Label(integrity, confidentiality, frozenset(capabilities))
        provenance = (source,) if source else ()
        return cls(value, label, provenance)

    @classmethod
    def clean(cls, value: Any) -> "Tainted":
        return cls(value, BOTTOM, ())

    # -- views -----------------------------------------------------------
    @property
    def text(self) -> str:
        if isinstance(self.value, str):
            return self.value
        return json.dumps(self.value, sort_keys=True, ensure_ascii=True)

    def derived(self, value: Any, *, drop_taint: bool = False) -> "Tainted":
        """A new value derived deterministically from this one."""
        if drop_taint:
            return Tainted.clean(value)
        return Tainted(value, self.label, self.provenance)

    # -- propagation rules ----------------------------------------------
    def slice(self, start: int, end: int | None = None,
              *, drop_taint: bool = False) -> "Tainted":
        return self.derived(self.text[start:end], drop_taint=drop_taint)

    def field(self, name: str, *, drop_taint: bool = False) -> "Tainted":
        return self.derived(extract_field(self.text, name),
                            drop_taint=drop_taint)

    def json_path(self, dotted: str, *, drop_taint: bool = False) -> "Tainted":
        """Walk a dotted path through a parsed JSON value."""
        try:
            current: Any = json.loads(self.text)
        except (ValueError, TypeError):
            return Tainted.clean("")
        for part in [p for p in dotted.split(".") if p]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.lstrip("-").isdigit():
                index = int(part)
                if -len(current) <= index < len(current):
                    current = current[index]
                else:
                    return Tainted.clean("")
            else:
                return Tainted.clean("")
        return self.derived(current, drop_taint=drop_taint)

    def concat(self, *others: "Tainted | str") -> "Tainted":
        return concat(self, *others)

    def encode(self, kind: str, *, drop_taint: bool = False) -> "Tainted":
        text = self.text
        if kind == "base64":
            encoded = b64_encode(text)
        elif kind == "hex":
            encoded = hex_encode(text)
        elif kind == "zwsp":
            encoded = zwsp_interleave(text)
        elif kind == "url":
            encoded = urllib.parse.quote(text, safe="")
        elif kind == "none":
            encoded = text
        else:
            raise ValueError("unsupported encoding: %s" % kind)
        return self.derived(encoded, drop_taint=drop_taint)

    def decode_all(self, *, drop_taint: bool = False) -> list["Tainted"]:
        """Taint-preserving decode of every candidate payload."""
        return [
            self.derived(candidate.payload, drop_taint=drop_taint)
            for candidate in decode_candidates(self.text)
        ]

    def fmt(self, template: str, *args: "Tainted | str",
            **kwargs: "Tainted | str") -> "Tainted":
        """Formatting inherits the join of the format arguments."""
        merged = join_values([self, *args, *kwargs.values()])
        text = template.format(*[as_tainted(a).text for a in args],
                               **{k: as_tainted(v).text
                                  for k, v in kwargs.items()})
        return Tainted(text, merged.label, merged.provenance)

    # -- serialization ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "label": self.label.to_dict(),
            "provenance": list(self.provenance),
        }

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        preview = self.text
        if len(preview) > 60:
            preview = preview[:57] + "..."
        return "%r [%s]" % (preview, self.label)


def as_tainted(value: "Tainted | Any") -> Tainted:
    if isinstance(value, Tainted):
        return value
    return Tainted.clean(value)


def join_values(values: Sequence["Tainted | Any"]) -> Tainted:
    """Join label and provenance over a sequence (label only in result)."""
    label = BOTTOM
    provenance: list[str] = []
    for item in values:
        wrapped = as_tainted(item)
        label = join(label, wrapped.label)
        for source in wrapped.provenance:
            if source not in provenance:
                provenance.append(source)
    return Tainted("", label, tuple(provenance))


def concat(*parts: "Tainted | Any") -> Tainted:
    """String concatenation; the result keeps the join of all inputs."""
    wrapped = [as_tainted(part) for part in parts]
    merged = join_values(wrapped)
    text = "".join(part.text for part in wrapped)
    return Tainted(text, merged.label, merged.provenance)
