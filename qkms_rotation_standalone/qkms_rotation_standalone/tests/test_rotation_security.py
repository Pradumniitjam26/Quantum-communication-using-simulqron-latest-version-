import unittest
from rotation_security import (
    RotationTimer, ControlledRotation, derive_control_key,
    build_rotation_hello, verify_rotation_hello,
    authenticate_control_message, verify_control_message,
)

class FakeClock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now

class RotationSecurityTests(unittest.TestCase):
    def setUp(self): self.key = bytes(range(32))

    def test_timer_due_at_five_minutes(self):
        c = FakeClock(); t = RotationTimer(300, c)
        self.assertFalse(t.check().due)
        c.now += 299; self.assertFalse(t.check().due)
        c.now += 1; self.assertTrue(t.check().due)
        t.mark_rotated(); self.assertFalse(t.check().due)

    def test_control_key_is_domain_and_session_bound(self):
        self.assertNotEqual(derive_control_key(self.key, "s1"), derive_control_key(self.key, "s2"))

    def test_valid_rotation_hello(self):
        msg = build_rotation_hello(key_id=22, session_id="new-session", epoch=2,
                                   bb84_key=self.key, previous_session_id="old-session")
        self.assertTrue(verify_rotation_hello(msg, self.key,
            expected_previous_session_id="old-session", minimum_epoch=2))

    def test_tampered_message_rejected(self):
        msg = build_rotation_hello(key_id=22, session_id="new-session", epoch=2,
                                   bb84_key=self.key, previous_session_id="old-session")
        msg["key_id"] = 23
        self.assertFalse(verify_rotation_hello(msg, self.key,
            expected_previous_session_id="old-session", minimum_epoch=2))

    def test_wrong_key_rejected(self):
        msg = build_rotation_hello(key_id=22, session_id="new-session", epoch=2,
                                   bb84_key=self.key, previous_session_id="old-session")
        self.assertFalse(verify_rotation_hello(msg, b"x" * 32,
            expected_previous_session_id="old-session", minimum_epoch=2))

    def test_old_epoch_and_old_session_rejected(self):
        msg = build_rotation_hello(key_id=22, session_id="new-session", epoch=1,
                                   bb84_key=self.key, previous_session_id="old-session")
        self.assertFalse(verify_rotation_hello(msg, self.key,
            expected_previous_session_id="old-session", minimum_epoch=2))
        msg2 = build_rotation_hello(key_id=22, session_id="new-session", epoch=2,
                                    bb84_key=self.key, previous_session_id="stale-session")
        self.assertFalse(verify_rotation_hello(msg2, self.key,
            expected_previous_session_id="old-session", minimum_epoch=2))

    def test_controlled_commit_requires_matching_ack(self):
        r = ControlledRotation()
        epoch, sid = r.prepare()
        with self.assertRaises(ValueError): r.commit(epoch, "wrong-session")
        self.assertEqual(r.epoch, 1)
        r.commit(epoch, sid)
        self.assertEqual(r.epoch, 2)

    def test_abort_does_not_advance_epoch(self):
        r = ControlledRotation(); r.prepare(); r.abort()
        self.assertEqual(r.epoch, 1)
        self.assertEqual(r.prepare()[0], 2)

    def test_duplicate_prepare_blocked(self):
        r = ControlledRotation(); r.prepare()
        with self.assertRaises(RuntimeError): r.prepare()

if __name__ == "__main__": unittest.main(verbosity=2)
