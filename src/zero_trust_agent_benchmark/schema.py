"""Trace data model and JSON-schema validation for Zero Trust Agent Benchmark."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import jsonschema

SVID_STATES = ("valid", "expired", "wrong_trust_domain", "missing", "forged", "revoked")
ATTESTATION_STATES = (
    "valid",
    "stale",
    "pcr_mismatch",
    "missing",
    "replayed_nonce",
    "bad_signature",
)
ORIGINS = ("user", "tool_output", "retrieved_doc", "mcp_server")
TRUST_OUTCOMES = ("benign", "suspicious", "malicious", "unknown")
ATTACK_FAMILIES = (
    "prompt_injection",
    "control_token",
    "tool_hijack",
    "tool_poisoning",
    "parser_confusion",
    "data_exfil",
    "priv_esc",
)

Label = Literal["attack", "benign"]
Split = Literal["dev", "test"]


@dataclass(slots=True)
class Agent:
    agent_id: str
    spiffe_id: str
    svid: str = "valid"
    attestation: str = "valid"
    trust_history: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    role: str = "assistant"


@dataclass(slots=True)
class Step:
    step: int
    tool: str
    args: dict[str, Any]
    context: dict[str, Any]
    malicious: bool = False


@dataclass(slots=True)
class Trace:
    trace_id: str
    split: Split
    label: Label
    family: str
    description: str
    agent: Agent
    steps: list[Step]
    secrets: list[str] = field(default_factory=list)
    template_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data.get("template_id") is None:
            data.pop("template_id", None)
        if not data.get("metadata"):
            data.pop("metadata", None)
        return data

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Trace:
        return cls(
            trace_id=d["trace_id"],
            split=d["split"],
            label=d["label"],
            family=d["family"],
            description=d["description"],
            agent=Agent(**dict(d["agent"])),
            steps=[Step(**s) for s in d["steps"]],
            secrets=list(d.get("secrets", [])),
            template_id=d.get("template_id"),
            metadata=dict(d.get("metadata", {})),
        )


TRACE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark/schema/trace-v1.json",
    "title": "Zero Trust Agent Benchmark trace v1",
    "type": "object",
    "additionalProperties": True,
    "required": [
        "trace_id",
        "split",
        "label",
        "family",
        "description",
        "agent",
        "steps",
        "secrets",
    ],
    "properties": {
        "trace_id": {"type": "string", "pattern": "^[a-z0-9-]+$"},
        "split": {"enum": ["dev", "test"]},
        "label": {"enum": ["attack", "benign"]},
        "family": {
            "type": "string",
            "pattern": "^(benign_[a-z0-9_]+|" + "|".join(ATTACK_FAMILIES) + ")$",
        },
        "description": {"type": "string"},
        "template_id": {"type": "string"},
        "metadata": {
            "type": "object",
            "additionalProperties": True,
            "properties": {"in_policy": {"type": "boolean"}},
        },
        "secrets": {"type": "array", "items": {"type": "string", "minLength": 8}},
        "agent": {
            "type": "object",
            "additionalProperties": True,
            "required": ["agent_id", "spiffe_id", "svid", "attestation", "trust_history"],
            "properties": {
                "agent_id": {"type": "string"},
                "spiffe_id": {"type": "string", "pattern": "^spiffe://[a-z0-9.-]+/.+$"},
                "svid": {"enum": list(SVID_STATES)},
                "attestation": {"enum": list(ATTESTATION_STATES)},
                "trust_history": {"type": "array", "items": {"enum": list(TRUST_OUTCOMES)}},
                "scopes": {"type": "array", "items": {"type": "string"}},
                "role": {"type": "string"},
            },
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["step", "tool", "args", "context", "malicious"],
                "properties": {
                    "step": {"type": "integer", "minimum": 0},
                    "tool": {"type": "string"},
                    "args": {"type": "object"},
                    "malicious": {"type": "boolean"},
                    "context": {
                        "type": "object",
                        "additionalProperties": True,
                        "required": ["origin", "content", "reasoning_tokens", "user_task"],
                        "properties": {
                            "origin": {"enum": list(ORIGINS)},
                            "content": {"type": "string"},
                            "reasoning_tokens": {"type": "integer", "minimum": 0},
                            "tool_description": {"type": "string"},
                            "declared_scopes": {"type": "array", "items": {"type": "string"}},
                            "user_task": {"type": "string"},
                            "raw_generation": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}

_VALIDATOR = jsonschema.Draft202012Validator(TRACE_SCHEMA)


def validate_trace(d: dict[str, Any]) -> None:
    """Raise ``jsonschema.ValidationError`` if *d* is not a valid trace, plus semantic checks."""
    _VALIDATOR.validate(d)
    steps = d["steps"]
    if [s["step"] for s in steps] != list(range(len(steps))):
        raise jsonschema.ValidationError("steps must be numbered 0..n-1")
    has_mal = any(s["malicious"] for s in steps)
    if d["label"] == "attack" and not has_mal:
        raise jsonschema.ValidationError("attack trace needs at least one malicious step")
    if d["label"] == "benign" and has_mal:
        raise jsonschema.ValidationError("benign trace must not contain malicious steps")
    if d["label"] == "benign" and not d["family"].startswith("benign_"):
        raise jsonschema.ValidationError("benign traces must use a benign_* family")
    if d["label"] == "attack" and d["family"].startswith("benign_"):
        raise jsonschema.ValidationError("attack traces must use an attack family")


def dump_traces(traces: Iterable[Trace], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for t in traces:
            data = t.to_dict()
            validate_trace(data)
            line = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            fh.write(line + "\n")
            n += 1
    return n


def iter_traces(path: Path, *, validate: bool = True) -> Iterator[Trace]:
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            d = json.loads(line)
            if validate:
                try:
                    validate_trace(d)
                except jsonschema.ValidationError as e:
                    raise ValueError(f"{path}:{lineno}: {e.message}") from e
            yield Trace.from_dict(d)
