import base64
import json
import time
import unittest

from vaptkit.jwt_check import decode_segment, jwt_weaknesses, looks_like_jwt


def b64url(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def build_jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{b64url(header)}.{b64url(payload)}.{signature}"


class DecodeSegmentTests(unittest.TestCase):
    def test_decodes_valid_segment(self):
        self.assertEqual(decode_segment(b64url({"alg": "HS256"})), {"alg": "HS256"})

    def test_none_for_invalid_base64(self):
        self.assertIsNone(decode_segment("not-valid-base64!!!"))

    def test_none_for_non_object_json(self):
        self.assertIsNone(decode_segment(base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode()))

    def test_none_for_non_json_payload(self):
        self.assertIsNone(decode_segment(base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()))


class LooksLikeJwtTests(unittest.TestCase):
    def test_three_segments_is_jwt_shaped(self):
        self.assertTrue(looks_like_jwt(build_jwt({"alg": "HS256"}, {"sub": "1"})))

    def test_opaque_token_is_not_jwt_shaped(self):
        self.assertFalse(looks_like_jwt("SYNTHETIC_TOKEN_admin"))

    def test_wrong_segment_count_is_not_jwt_shaped(self):
        self.assertFalse(looks_like_jwt("a.b"))
        self.assertFalse(looks_like_jwt("a.b.c.d"))

    def test_empty_segment_is_not_jwt_shaped(self):
        self.assertFalse(looks_like_jwt(".b.c"))


class JwtWeaknessesTests(unittest.TestCase):
    def test_opaque_token_has_no_weaknesses(self):
        self.assertEqual(jwt_weaknesses("SYNTHETIC_TOKEN_admin"), [])

    def test_well_formed_short_lived_token_has_no_weaknesses(self):
        now = int(time.time())
        token = build_jwt({"alg": "RS256"}, {"sub": "1", "iat": now, "exp": now + 900})
        self.assertEqual(jwt_weaknesses(token), [])

    def test_alg_none_is_flagged(self):
        now = int(time.time())
        token = build_jwt({"alg": "none"}, {"sub": "1", "iat": now, "exp": now + 900})
        self.assertIn("alg_none", jwt_weaknesses(token))

    def test_missing_alg_is_treated_as_none(self):
        now = int(time.time())
        token = build_jwt({}, {"sub": "1", "iat": now, "exp": now + 900})
        self.assertIn("alg_none", jwt_weaknesses(token))

    def test_missing_expiry_is_flagged(self):
        token = build_jwt({"alg": "HS256"}, {"sub": "1"})
        self.assertIn("no_expiry", jwt_weaknesses(token))

    def test_long_lived_token_is_flagged(self):
        now = int(time.time())
        token = build_jwt({"alg": "HS256"}, {"sub": "1", "iat": now, "exp": now + 365 * 24 * 3600})
        self.assertIn("long_lived", jwt_weaknesses(token))

    def test_short_lived_token_without_iat_is_not_flagged_long_lived(self):
        now = int(time.time())
        token = build_jwt({"alg": "HS256"}, {"sub": "1", "exp": now + 365 * 24 * 3600})
        self.assertNotIn("long_lived", jwt_weaknesses(token))

    def test_unparseable_segment_has_no_weaknesses(self):
        token = "not-base64!!.also-not-base64!!.sig"
        self.assertEqual(jwt_weaknesses(token), [])


if __name__ == "__main__":
    unittest.main()
