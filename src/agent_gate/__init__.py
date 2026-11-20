"""agent-gate: capability-taint isolation for LLM tool-calling agents.

The package is organised as a reference monitor:

``labels`` / ``lattice``
    the value domain and its algebraic structure;
``taint``
    propagation of labels through string and encoding operations;
``policy``
    the declarative flow rules and the approval authority;
``tools``
    sandboxed sinks and sources with declared capabilities;
``runtime``
    plan execution with a mandatory check before every call;
``backends``
    deterministic (and optionally model-driven) planners;
``scenarios`` / ``metrics``
    corpus construction and evaluation.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .labels import CAPABILITIES, Confidentiality, Integrity, Label
from .lattice import BOTTOM, TOP, declassify, join, join_all, leq, meet
from .policy import ApprovalAuthority, Decision, Policy
from .runtime import GuardConfig, Plan, PolicyViolation, RunResult, Runtime, Step
from .taint import Tainted, detect_leak
from .tools import EgressRecorder, Sandbox, Tools

__all__ = [
    "BOTTOM",
    "CAPABILITIES",
    "TOP",
    "ApprovalAuthority",
    "Confidentiality",
    "Decision",
    "EgressRecorder",
    "GuardConfig",
    "Integrity",
    "Label",
    "Plan",
    "Policy",
    "PolicyViolation",
    "RunResult",
    "Runtime",
    "Sandbox",
    "Step",
    "Tainted",
    "Tools",
    "declassify",
    "detect_leak",
    "join",
    "join_all",
    "leq",
    "meet",
]
