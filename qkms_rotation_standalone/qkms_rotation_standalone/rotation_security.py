"""Standalone primitives for controlled BB84 QKMS session-key rotation.

No network or QKMS database access is performed here. The caller must load and
validate an ACTIVE 256-bit BB84 key locally on each endpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROTATION_INTERVAL_SECONDS = 300
PROTOCOL_LABEL = b"QKMS-VIDEO-ROTATION-CONTROL-v1"


def derive_control_key(bb84_key: bytes, session_id: str) -> bytes:
    """Derive a domain-separated 256-bit control-authentication key."""
    if not isinstance(bb84_key, bytes) or len(bb84_key) != 32:
        raise ValueError("BB84 key must be exactly 32 bytes (256 bits)")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=hashlib.sha256(session_id.encode("utf-8")).digest(),
        info=PROTOCOL_LABEL,
    ).derive(bb84_key)


def _canonical_message(message: dict) -> bytes:
    if not isinstance(message, dict):
        raise TypeError("control message must be a dictionary")
    # MAC is excluded from the authenticated body.
    body = {k: v for k, v in message.items() if k != "mac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def authenticate_control_message(message: dict, control_key: bytes) -> dict:
    if len(control_key) != 32:
        raise ValueError("control key must be 32 bytes")
    signed = dict(message)
    signed.pop("mac", None)
    signed["mac"] = hmac.new(control_key, _canonical_message(signed), hashlib.sha256).hexdigest()
    return signed


def verify_control_message(message: dict, control_key: bytes) -> bool:
    if not isinstance(message, dict) or not isinstance(message.get("mac"), str):
        return False
    supplied = message["mac"]
    expected = hmac.new(control_key, _canonical_message(message), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def build_rotation_hello(*, key_id: int, session_id: str, epoch: int,
                         bb84_key: bytes, previous_session_id: Optional[str] = None) -> dict:
    if int(key_id) <= 0 or int(epoch) <= 0 or not session_id:
        raise ValueError("key_id, epoch and session_id must be valid")
    control_key = derive_control_key(bb84_key, session_id)
    message = {
        "type": "ROTATION_HELLO", "version": 1,
        "key_id": int(key_id), "session_id": session_id,
        "epoch": int(epoch), "protocol": "BB84", "key_length": 256,
        "previous_session_id": previous_session_id,
    }
    return authenticate_control_message(message, control_key)


def verify_rotation_hello(message: dict, bb84_key: bytes, *,
                          expected_previous_session_id: Optional[str],
                          minimum_epoch: int) -> bool:
    try:
        if message.get("type") != "ROTATION_HELLO" or message.get("version") != 1:
            return False
        if message.get("protocol") != "BB84" or message.get("key_length") != 256:
            return False
        if int(message.get("key_id", 0)) <= 0 or int(message.get("epoch", 0)) < minimum_epoch:
            return False
        if message.get("previous_session_id") != expected_previous_session_id:
            return False
        key = derive_control_key(bb84_key, str(message.get("session_id", "")))
        return verify_control_message(message, key)
    except (TypeError, ValueError, KeyError):
        return False


@dataclass(frozen=True)
class RotationDue:
    due: bool
    elapsed_seconds: float
    interval_seconds: float


class RotationTimer:
    """Monotonic timer; call mark_rotated only after peer ACK and commit."""
    def __init__(self, interval_seconds: int = ROTATION_INTERVAL_SECONDS,
                 clock: Callable[[], float] = time.monotonic):
        if interval_seconds <= 0:
            raise ValueError("rotation interval must be positive")
        self.interval_seconds = float(interval_seconds)
        self._clock = clock
        self._last_success = clock()
        self._lock = threading.Lock()

    def check(self) -> RotationDue:
        with self._lock:
            elapsed = max(0.0, self._clock() - self._last_success)
        return RotationDue(elapsed >= self.interval_seconds, elapsed, self.interval_seconds)

    def mark_rotated(self) -> None:
        with self._lock:
            self._last_success = self._clock()


class ControlledRotation:
    """Two-phase local state helper; transport/media pause remains caller-owned.

    Sequence: prepare -> authenticated peer acknowledgement -> commit.
    A failed/aborted attempt never advances the timer or active epoch.
    """
    def __init__(self, initial_epoch: int = 1):
        if initial_epoch < 1:
            raise ValueError("initial_epoch must be >= 1")
        self.epoch = initial_epoch
        self.pending_epoch = None
        self.pending_session_id = None
        self._lock = threading.Lock()

    def prepare(self) -> tuple[int, str]:
        with self._lock:
            if self.pending_epoch is not None:
                raise RuntimeError("rotation already pending")
            self.pending_epoch = self.epoch + 1
            self.pending_session_id = secrets.token_hex(16)
            return self.pending_epoch, self.pending_session_id

    def commit(self, acknowledged_epoch: int, acknowledged_session_id: str) -> None:
        with self._lock:
            if self.pending_epoch is None:
                raise RuntimeError("no pending rotation")
            if acknowledged_epoch != self.pending_epoch or acknowledged_session_id != self.pending_session_id:
                raise ValueError("rotation acknowledgement mismatch")
            self.epoch = self.pending_epoch
            self.pending_epoch = None
            self.pending_session_id = None

    def abort(self) -> None:
        with self._lock:
            self.pending_epoch = None
            self.pending_session_id = None
