"""Sandboxed tool implementations.

Every tool is mock or sandboxed by construction:

* ``http_get`` reads from an in-process page registry, never the network;
* ``http_post`` appends to an in-process egress recorder, never the network;
* ``read_file`` / ``write_file`` are confined to a temporary directory under
  the project, with path traversal rejected.

Each tool declares one capability from :data:`TOOL_CAPS`.  The capability is
what the policy reasons about; tool names are only a convenience for the
scenario author.  Adding a tool means adding one entry here and nothing else,
which is a small but real property: the monitor cannot be extended into
permissiveness by a new tool integration.

Labels survive disk round-trips.  Writing a secret and reading it back does
not launder it, because the sandbox records the label at write time and
restores it at read time.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .labels import Confidentiality, Integrity, Label
from .lattice import BOTTOM
from .taint import Tainted

#: ``http_get`` is deliberately *not* a ``NET`` sink.  Reading a page is an
#: ingress operation and a source of untrusted data; treating it as an egress
#: sink would block fetching rather than exfiltration and would hide the
#: property under test behind an over-broad rule.
TOOL_CAPS: dict[str, str] = {
    "read_file": "FS_READ",
    "write_file": "FS_WRITE",
    "http_get": "NET_IN",
    "http_post": "NET",
    "summarize": "LLM",
    "declassify": "DECLASSIFY",
}

DEFAULT_PAGE = (
    "Generic third-party page. Nothing relevant to the task was found here.\n"
)


class ToolError(RuntimeError):
    """Raised when a tool cannot fulfil a call inside the sandbox."""


def compact(text: str) -> str:
    return " ".join(text.split())


def summarize_text(text: str, limit: int = 160) -> str:
    """Deterministic summariser used by both the tool and the plan builder."""
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]
    return "SUMMARY(%s): %s" % (digest, compact(text)[:limit])


@dataclass
class Sandbox:
    """A directory tree plus the label attached to each file in it."""

    root: Path
    labels: dict[str, Label]

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.labels = {
            self._normalise(path): label
            for path, label in dict(self.labels or {}).items()
        }

    @staticmethod
    def _normalise(path: str) -> str:
        return path.replace("\\", "/").lstrip("./")

    def _resolve(self, path: str, *, create: bool = False) -> Path:
        relative = self._normalise(path)
        if not relative or relative.startswith("../") or "/../" in relative:
            raise ToolError("path escapes sandbox: %r" % path)
        target = (self.root / relative).resolve()
        root = self.root.resolve()
        if target != root and not target.is_relative_to(root):
            raise ToolError("path escapes sandbox: %r" % path)
        if create:
            target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def add(self, path: str, content: str, label: Label) -> None:
        target = self._resolve(path, create=True)
        target.write_text(content, encoding="utf-8")
        self.labels[self._normalise(path)] = label

    def read(self, path: str) -> tuple[str, Label]:
        relative = self._normalise(path)
        target = self._resolve(path)
        if not target.exists():
            raise ToolError("no such file in sandbox: %r" % path)
        label = self.labels.get(relative)
        if label is None:
            # A file that appeared without a declared label is untrusted by
            # default: fail closed, never open.
            label = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
        return target.read_text(encoding="utf-8"), label

    def write(self, path: str, content: str, label: Label) -> int:
        target = self._resolve(path, create=True)
        target.write_text(content, encoding="utf-8")
        self.labels[self._normalise(path)] = label
        return len(content.encode("utf-8"))

    def snapshot(self) -> dict[str, Any]:
        return {
            path: label.to_dict()
            for path, label in sorted(self.labels.items())
        }


class EgressRecorder:
    """Collects outbound fragments; the only observation point for leaks."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, step_id: str, url: str, body: str) -> None:
        self.records.append(
            {
                "step": step_id,
                "url": url,
                "body": body,
                "bytes": len(body.encode("utf-8")),
            }
        )

    def clear(self) -> None:
        self.records.clear()

    def bodies(self) -> str:
        """Concatenation of every body, in call order.

        Concatenating is what makes split exfiltration measurable: two
        fragments that are individually clean reassemble into the canary
        here, which is exactly the adversary's assumption.
        """
        return "".join(record["body"] for record in self.records)

    def payloads(self) -> list[str]:
        per_call = [
            "%s\n%s" % (record["url"], record["body"])
            for record in self.records
        ]
        return per_call + [self.bodies()]

    def to_dict(self) -> dict[str, Any]:
        return {"records": list(self.records), "total_bytes": sum(
            record["bytes"] for record in self.records
        )}


class Tools:
    """The reference tool set bound to one sandbox and one egress recorder."""

    def __init__(
        self,
        sandbox: Sandbox,
        egress: EgressRecorder | None = None,
        pages: Mapping[str, tuple[str, Label]] | None = None,
        summarise_limit: int = 160,
    ) -> None:
        self.sandbox = sandbox
        self.egress = egress or EgressRecorder()
        self.pages: dict[str, tuple[str, Label]] = dict(pages or {})
        self.sources: dict[str, Label] = {}
        self.summarise_limit = summarise_limit
        self.calls: list[dict[str, Any]] = []

    # -- capability lookup ----------------------------------------------
    @staticmethod
    def capability(tool: str) -> str:
        try:
            return TOOL_CAPS[tool]
        except KeyError:
            raise ToolError("unknown tool: %r" % tool) from None

    # -- dispatch --------------------------------------------------------
    def call(self, tool: str, args: Mapping[str, Tainted],
             step_id: str = "") -> Tainted:
        self.capability(tool)  # validate before touching anything
        if tool == "read_file":
            return self.read_file(args["path"].text)
        if tool == "write_file":
            return self.write_file(args["path"].text, args["text"])
        if tool == "http_get":
            return self.http_get(args["url"].text, step_id)
        if tool == "http_post":
            return self.http_post(args["url"].text, args["body"], step_id)
        if tool == "summarize":
            return self.summarize(args["text"])
        raise ToolError("tool %r has no implementation" % tool)

    # -- implementations -------------------------------------------------
    def read_file(self, path: str) -> Tainted:
        content, label = self.sandbox.read(path)
        source = "src:file:%s" % Sandbox._normalise(path)
        self.sources[source] = label
        self.calls.append({"tool": "read_file", "path": path})
        return Tainted(content, label, (source,))

    def write_file(self, path: str, text: Tainted) -> Tainted:
        payload = text if isinstance(text, Tainted) else Tainted.clean(text)
        written = self.sandbox.write(path, payload.text, payload.label)
        self.calls.append({"tool": "write_file", "path": path,
                           "bytes": written})
        return Tainted("wrote %d bytes" % written, BOTTOM, ())

    def http_get(self, url: str, step_id: str = "") -> Tainted:
        content, label = self.pages.get(
            url,
            (DEFAULT_PAGE, Label(Integrity.UNTRUSTED,
                                 Confidentiality.PUBLIC)),
        )
        source = "src:http_get:%s" % url
        self.sources[source] = label
        self.calls.append({"tool": "http_get", "url": url})
        return Tainted(content, label, (source,))

    def http_post(self, url: str, body: Tainted,
                  step_id: str = "") -> Tainted:
        payload = body if isinstance(body, Tainted) else Tainted.clean(body)
        self.egress.record(step_id, url, payload.text)
        self.calls.append({"tool": "http_post", "url": url,
                           "bytes": len(payload.text)})
        return Tainted("ok", BOTTOM, ())

    def summarize(self, text: Tainted) -> Tainted:
        payload = text if isinstance(text, Tainted) else Tainted.clean(text)
        summary = summarize_text(payload.text, self.summarise_limit)
        self.calls.append({"tool": "summarize",
                           "input_bytes": len(payload.text)})
        return Tainted(summary, payload.label, payload.provenance)

    # -- lifecycle -------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "tools": sorted(TOOL_CAPS),
            "sandbox_files": self.sandbox.snapshot(),
            "egress": self.egress.to_dict(),
            "calls": list(self.calls),
        }


def make_runtime_dir(base: Path) -> Path:
    """Create a per-run scratch directory under the project results tree."""
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="run-", dir=str(base)))


def drop_runtime_dir(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def json_dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)
