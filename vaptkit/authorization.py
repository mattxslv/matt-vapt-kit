"""Evidence evaluation for local synthetic ownership and workflow exercises.

These evaluators perform no requests. They are not enabled by the live role runner.
Raw object fields are compared in memory, never included in returned evidence.
"""
from dataclasses import dataclass

from .exposure import content_class
from .roles import json_object


@dataclass(frozen=True)
class ObjectExpectation:
    identifier: str
    owner: str
    private_marker: str


@dataclass(frozen=True)
class ObjectEvidence:
    status: int
    object_matches: bool
    body_assessed: bool = False
    phase: str | None = None
    revision: int | None = None
    actor_matches: bool = False
    action_matches: bool = False


@dataclass(frozen=True)
class TransitionEvidence:
    before: ObjectEvidence
    action_status: int
    after: ObjectEvidence


def observe_object(status: int, headers: dict, body: bytes, expected: ObjectExpectation,
                   *, actor: str | None = None, action: str | None = None) -> ObjectEvidence:
    value = json_object(body) if content_class(headers) == "json" else None
    data = value.get("data") if value else None
    matched = isinstance(data, dict) and (
        data.get("id") == expected.identifier and data.get("owner") == expected.owner
        and data.get("private_note") == expected.private_marker
    )
    if not matched:
        return ObjectEvidence(status, False, value is not None)
    phase = data.get("phase")
    revision = data.get("revision")
    return ObjectEvidence(
        status, True, True,
        phase if phase in ("draft", "submitted", "reviewed", "approved") else None,
        revision if type(revision) is int and revision >= 0 else None,
        actor is not None and data.get("last_actor") == actor,
        action is not None and data.get("last_action") == action,
    )


def readable(item: ObjectEvidence) -> bool:
    return 200 <= item.status < 300 and item.object_matches


def evaluate_read(control: ObjectEvidence, attempts: list[ObjectEvidence], *, allowed: bool) -> str:
    if not readable(control) or len(attempts) != 2:
        return "inconclusive"
    if allowed:
        return "allowed" if all(readable(item) for item in attempts) else "inconclusive"
    # An error status does not excuse a response body that discloses the protected object.
    if all(item.object_matches for item in attempts):
        return "violation"
    if all(item.status in (401, 403, 404) and item.body_assessed and not item.object_matches for item in attempts):
        return "denied"
    return "inconclusive"


def transitioned(item: TransitionEvidence, from_phase: str, to_phase: str) -> bool:
    before, after = item.before, item.after
    return (
        readable(before) and readable(after) and before.phase == from_phase and after.phase == to_phase
        and before.revision is not None and after.revision == before.revision + 1
        and after.actor_matches and after.action_matches
    )


def evaluate_transition(control: TransitionEvidence, attempts: list[TransitionEvidence], *,
                        control_from: str, from_phase: str, to_phase: str, allowed: bool) -> str:
    if not transitioned(control, control_from, to_phase) or len(attempts) != 2:
        return "inconclusive"
    changes = [transitioned(item, from_phase, to_phase) for item in attempts]
    if all(changes):
        return "allowed" if allowed else "violation"
    if allowed:
        return "inconclusive"
    for item in attempts:
        before, after = item.before, item.after
        if (not readable(before) or not readable(after) or before.phase != from_phase
                or before.revision is None or after.phase != before.phase or after.revision != before.revision
                or item.action_status not in (401, 403, 409)):
            return "inconclusive"
    return "denied"
