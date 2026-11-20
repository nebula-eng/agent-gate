"""Taint propagation, including the encoding paths that defeat string filters."""

from __future__ import annotations

import base64
import unittest

from agent_gate.labels import Confidentiality, Integrity, Label
from agent_gate.taint import (
    Tainted,
    b64_decode,
    b64_encode,
    canary_forms,
    concat,
    decode_candidates,
    detect_leak,
    hex_decode,
    hex_encode,
    strip_zero_width,
    zwsp_encode,
    zwsp_interleave,
)

CANARY = "CANARY-0123456789abcdef"
SECRET_LABEL = Label(Integrity.TRUSTED, Confidentiality.SECRET)


def secret_value(text: str = "API_KEY: " + CANARY) -> Tainted:
    return Tainted(text, SECRET_LABEL, ("src:file:secrets/credentials.txt",))


class TestPropagation(unittest.TestCase):
    def test_assignment_keeps_label(self) -> None:
        value = secret_value()
        self.assertTrue(value.label.confidentiality is Confidentiality.SECRET)
        self.assertEqual(value.provenance,
                         ("src:file:secrets/credentials.txt",))

    def test_concat_joins_labels(self) -> None:
        left = secret_value()
        right = Tainted.clean(" suffix")
        combined = concat(left, right)
        self.assertEqual(combined.label.confidentiality,
                         Confidentiality.SECRET)
        self.assertIn(CANARY, combined.text)

    def test_concat_with_untrusted_raises_integrity(self) -> None:
        clean = Tainted.clean("a")
        dirty = Tainted("b", Label(Integrity.UNTRUSTED,
                                   Confidentiality.PUBLIC), ("src:web",))
        self.assertEqual(concat(clean, dirty).label.integrity,
                         Integrity.UNTRUSTED)

    def test_format_propagates(self) -> None:
        value = secret_value().fmt("payload={key}", key=secret_value())
        self.assertEqual(value.label.confidentiality,
                         Confidentiality.SECRET)
        self.assertIn(CANARY, value.text)

    def test_slice_keeps_label_and_provenance(self) -> None:
        piece = secret_value(CANARY).slice(0, 6)
        self.assertEqual(piece.text, "CANARY")
        self.assertEqual(piece.label, SECRET_LABEL)
        self.assertEqual(piece.provenance,
                         ("src:file:secrets/credentials.txt",))

    def test_field_extraction_keeps_label(self) -> None:
        content = "# keys\nAPI_KEY: %s\nOTHER: x\n" % CANARY
        value = Tainted(content, SECRET_LABEL, ("src:file:k",)).field("API_KEY")
        self.assertEqual(value.text, CANARY)
        self.assertEqual(value.label.confidentiality, Confidentiality.SECRET)

    def test_json_extraction_keeps_label(self) -> None:
        payload = '{"a": {"b": "%s"}}' % CANARY
        value = Tainted(payload, SECRET_LABEL, ("src:file:j",)).json_path("a.b")
        self.assertEqual(value.text, CANARY)
        self.assertEqual(value.label, SECRET_LABEL)

    def test_json_extraction_missing_path_is_clean(self) -> None:
        value = Tainted('{"a": 1}', SECRET_LABEL, ("src:x",)).json_path("z")
        self.assertEqual(value.text, "")
        self.assertEqual(value.label.confidentiality,
                         Confidentiality.PUBLIC)

    def test_provenance_is_union(self) -> None:
        merged = concat(Tainted("a", SECRET_LABEL, ("s1",)),
                        Tainted("b", SECRET_LABEL, ("s2",)))
        self.assertEqual(merged.provenance, ("s1", "s2"))

    def test_drop_taint_is_explicitly_unsound(self) -> None:
        value = secret_value(CANARY)
        self.assertEqual(value.slice(0, 6).label, SECRET_LABEL)
        self.assertEqual(value.slice(0, 6, drop_taint=True).label,
                         Label())


class TestEncodings(unittest.TestCase):
    def test_base64_roundtrip(self) -> None:
        self.assertEqual(b64_decode(b64_encode(CANARY)), CANARY)

    def test_hex_roundtrip(self) -> None:
        self.assertEqual(hex_decode(hex_encode(CANARY)), CANARY)

    def test_base64_candidate_found(self) -> None:
        payload = "body=" + b64_encode(CANARY)
        encodings = {item.encoding for item in decode_candidates(payload)}
        self.assertIn("base64", encodings)
        self.assertTrue(
            any(CANARY in item.payload
                for item in decode_candidates(payload))
        )

    def test_hex_candidate_found(self) -> None:
        payload = "body=" + hex_encode(CANARY)
        self.assertTrue(
            any(CANARY in item.payload
                for item in decode_candidates(payload))
        )

    def test_zero_width_bits_roundtrip(self) -> None:
        payload = "x" + zwsp_encode(CANARY)
        self.assertTrue(
            any(CANARY in item.payload
                for item in decode_candidates(payload))
        )
        self.assertNotIn(CANARY, payload)

    def test_zero_width_interleave_stripped(self) -> None:
        payload = zwsp_interleave(CANARY)
        self.assertNotIn(CANARY, payload)
        self.assertEqual(strip_zero_width(payload), CANARY)
        self.assertTrue(detect_leak(payload, CANARY))

    def test_percent_candidate_found(self) -> None:
        payload = "%43%41%4E%41%52%59%2D%30%31"
        self.assertTrue(
            any(item.encoding == "percent"
                for item in decode_candidates(payload))
        )

    def test_decode_all_inherits_taint(self) -> None:
        value = secret_value(b64_encode(CANARY)).decode_all()
        self.assertTrue(value)
        self.assertEqual(value[0].label, SECRET_LABEL)

    def test_encode_inherits_taint(self) -> None:
        for kind in ("base64", "hex", "zwsp", "url"):
            encoded = secret_value("API_KEY: " + CANARY).encode(kind)
            self.assertEqual(encoded.label, SECRET_LABEL, kind)
            self.assertNotEqual(encoded.text, CANARY, kind)


class TestLeakDetection(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(detect_leak("x %s y" % CANARY, CANARY))

    def test_base64(self) -> None:
        self.assertTrue(detect_leak(b64_encode("id:" + CANARY), CANARY))

    def test_hex(self) -> None:
        self.assertTrue(detect_leak(hex_encode(CANARY), CANARY))

    def test_form_set_covers_encodings(self) -> None:
        forms = canary_forms(CANARY)
        self.assertIn(CANARY, forms)
        self.assertIn(base64.b64encode(CANARY.encode()).decode(), forms)
        self.assertIn(hex_encode(CANARY), forms)

    def test_absent_canary_not_detected(self) -> None:
        self.assertFalse(detect_leak("nothing to see", CANARY))
        self.assertFalse(detect_leak("CANARY-ffffffffffffffff", CANARY))

    def test_split_fragments_reassemble(self) -> None:
        first, second = CANARY[:4], CANARY[4:]
        self.assertFalse(detect_leak(first, CANARY))
        self.assertFalse(detect_leak(second, CANARY))
        self.assertTrue(detect_leak(first + second, CANARY))

    def test_url_encoded_detected(self) -> None:
        payload = "q=%3C" + CANARY + "%3E"
        self.assertTrue(detect_leak(payload, CANARY))

    def test_double_encoded_base64(self) -> None:
        inner = b64_encode(CANARY)
        outer = b64_encode(inner)
        self.assertTrue(detect_leak(outer, CANARY))


if __name__ == "__main__":
    unittest.main()
