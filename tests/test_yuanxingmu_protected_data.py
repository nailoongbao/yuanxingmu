"""Pure host bindings with synthetic sources; no model, process, or filesystem."""
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from yuanxingmu.protected_data import (
    HostProtectedData, HostResource, ProtectedDataError, MAX_RESOURCE_BYTES,
)
from yuanxingmu.protected_fields import POLICY_VERSION


def source(text):
    return HostResource(text, hashlib.sha256(text.encode("utf-8")).hexdigest())


def private_json(value):
    return json.dumps(value, ensure_ascii=True).encode("utf-8")


class ProtectedDataTests(unittest.TestCase):
    def setUp(self):
        self.resources = {
            "quote": source("客户公开报价：198000元。\n内部底价为162000元，不能展示。\n"),
            "service": source('api_key = "synthetic-api-ABC-123"\nservice: public-demo\n'),
        }
        self.data = HostProtectedData.compile(self.resources)

    def assert_refused(self, operation, code=None):
        with self.assertRaises(ProtectedDataError) as caught:
            operation()
        if code:
            self.assertEqual(code, caught.exception.code)
        for private in ("162000", "synthetic-api-ABC-123"):
            self.assertNotIn(private, str(caught.exception))
            self.assertNotIn(private, repr(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_real_sources_mask_before_model_and_match_across_resources(self):
        quote = self.data.redacted("quote", self.resources["quote"].sha256)
        service = self.data.redacted("service", self.resources["service"].sha256)
        self.assertIn("198000元", quote)
        self.assertNotIn("162000", quote)
        self.assertNotIn("synthetic-api-ABC-123", service)
        matches = self.data.match_output("内部金额是16.2万元；凭据 synthetic-api-ABC-123。")
        self.assertEqual({"r0001_f0001", "r0002_f0001"}, {item.field_id for item in matches})
        self.assertEqual(2, len(matches))
        self.assertEqual((), self.data.match_output("客户公开报价为198000元，准备提交。"))

    def test_private_roundtrip_recompiles_and_canonicalizes_but_public_data_is_value_free(self):
        raw = self.data.to_private_json()
        loaded = HostProtectedData.from_private_json(raw, resources=self.resources)
        self.assertEqual(raw, loaded.to_private_json())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), loaded.binding_digest())
        reordered = dict(reversed(list(json.loads(raw).items())))
        alternate = json.dumps(reordered, ensure_ascii=False, indent=4).encode("utf-8")
        self.assertEqual(raw, HostProtectedData.from_private_json(alternate, resources=self.resources).to_private_json())
        self.assertIn(b"162000", raw)  # Deliberately private, not an encrypted export.
        self.assertIn(b"synthetic-api-ABC-123", raw)
        summary = self.data.public_summary()
        self.assertEqual({"schema_version": 1, "rules_version": POLICY_VERSION,
                          "resource_count": 2, "field_count": 2}, summary)
        public = json.dumps(summary) + repr(self.data) + repr(self.resources["quote"])
        public += repr(self.data.match_output("162000元"))
        for private in ("162000", "synthetic-api-ABC-123", self.resources["quote"].sha256,
                        self.data.binding_digest(), "quote", "service"):
            self.assertNotIn(private, public)

    def test_every_source_fragment_range_mask_and_field_binding_is_revalidated(self):
        original = json.loads(self.data.to_private_json())
        mutations = [
            lambda item: item.update(schema_version=True),
            lambda item: item.update(schema_version=1.0),
            lambda item: item.update(schema_version=2),
            lambda item: item.update(rules_version="future_rules"),
            lambda item: item.update(extra="synthetic-api-ABC-123"),
            lambda item: item["resources"].pop(),
            lambda item: item["resources"].reverse(),
            lambda item: item["resources"].append(item["resources"][0]),
            lambda item: item["resources"][0].update(name="service"),
            lambda item: item["resources"][0].update(source_sha256="0" * 64),
            lambda item: item["resources"][0].update(source_bytes=1),
            lambda item: item["resources"][0].update(parsed_format="json"),
            lambda item: item["resources"][0].update(masked_text="162000"),
            lambda item: item["resources"][0].update(fields=[]),
        ]
        for name, replacement in (
            ("field_id", "r0002_f0001"), ("source_field_id", "f9999"), ("kind", "credential"),
            ("label", "public_price"), ("value", "198000"), ("source_fragment", "198000"),
            ("source_start", 0), ("source_end", 1), ("source_byte_start", 0),
            ("source_byte_end", 1), ("source_sha256", "0" * 64),
        ):
            mutations.append(lambda item, name=name, replacement=replacement:
                             item["resources"][0]["fields"][0].update({name: replacement}))
        mutations.append(lambda item: item["resources"][0]["fields"][0].pop("source_fragment"))
        mutations.append(lambda item: item["resources"][0]["fields"][0].update(unexpected=True))
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = json.loads(json.dumps(original))
                mutation(changed)
                self.assert_refused(lambda: HostProtectedData.from_private_json(private_json(changed), resources=self.resources))

    def test_missing_corrupt_or_duplicate_json_does_not_create_empty_protection(self):
        for raw in (None, "", b"", b"null", b"{}", b"[]", b"{", b"\xff",
                    b'{"schema_version":1,"schema_version":1,"rules_version":"explicit_labels_v1","resources":[]}',
                    b'{"schema_version":NaN,"rules_version":"explicit_labels_v1","resources":[]}',
                    self.data.to_private_json() + b"null"):
            with self.subTest(raw_type=type(raw).__name__):
                self.assert_refused(lambda: HostProtectedData.from_private_json(raw, resources=self.resources))
        nested_duplicate = self.data.to_private_json().replace(b'"kind":"internal_price"',
            b'"kind":"internal_price","kind":"internal_price"', 1)
        self.assert_refused(lambda: HostProtectedData.from_private_json(nested_duplicate, resources=self.resources))

    def test_host_source_replacement_missing_resource_or_new_resource_refuses_reload(self):
        raw = self.data.to_private_json()
        variants = [None, {}, {"quote": self.resources["quote"]},
                    {**self.resources, "quote": source("公开报价198000元，资料已替换。")},
                    {**self.resources, "new": source("public extra source")},
                    {"renamed": self.resources["quote"], "service": self.resources["service"]}]
        for resources in variants:
            with self.subTest(resources_type=type(resources).__name__):
                self.assert_refused(lambda: HostProtectedData.from_private_json(raw, resources=resources))
        self.assert_refused(lambda: HostResource("replacement source", self.resources["quote"].sha256),
                            "host_resource_sha256_mismatch")

    def test_empty_protection_still_binds_every_real_source(self):
        resources = {"public": source("公开报价198000元。订单号A162000，日期2026-09-12。")}
        data = HostProtectedData.compile(resources)
        self.assertEqual(0, data.public_summary()["field_count"])
        self.assertEqual(resources["public"].text, data.redacted("public", resources["public"].sha256))
        raw = data.to_private_json()
        self.assertEqual(raw, HostProtectedData.from_private_json(raw, resources=resources).to_private_json())
        self.assert_refused(lambda: HostProtectedData.from_private_json(raw, resources={}))
        changed = {"public": source("公开报价199000元。订单号A162000，日期2026-09-12。")}
        self.assert_refused(lambda: HostProtectedData.from_private_json(raw, resources=changed))
        self.assertNotEqual(data.binding_digest(), HostProtectedData.compile(changed).binding_digest())
        empty = HostProtectedData.compile({})
        self.assertEqual(empty.to_private_json(), HostProtectedData.from_private_json(empty.to_private_json(), resources={}).to_private_json())
        self.assert_refused(lambda: HostProtectedData.from_private_json(empty.to_private_json(), resources=resources))

    def test_cross_resource_repeated_secret_cannot_escape_through_public_source(self):
        resources = {"private": source("内部底价162000元。"), "public": source("报价资料里的金额是16.2万元。")}
        self.assert_refused(lambda: HostProtectedData.compile(resources), "protected_data_cross_resource_disclosure")
        resources = {"private": source("api_key: synthetic-api-ABC-123"),
                     "public": source("日志显示 synthetic-api-ABC-123")}
        self.assert_refused(lambda: HostProtectedData.compile(resources), "protected_data_cross_resource_disclosure")

    def test_cross_resource_ids_are_unique_and_same_values_are_not_dropped(self):
        resources = {"b": source("内部底价162000元。"), "a": source("内部底价162000元。")}
        data = HostProtectedData.compile(resources)
        self.assertEqual({"r0001_f0001", "r0002_f0001"}, {m.field_id for m in data.match_output("162000")})
        reverse = dict(reversed(list(resources.items())))
        self.assertEqual(data.to_private_json(), HostProtectedData.compile(reverse).to_private_json())

    def test_cross_resource_json_escapes_keys_arrays_and_duplicate_values_are_checked(self):
        private = source("api_key: synthetic-api-ABC-123")
        escaped = "synthetic\\u002dapi-ABC-123"
        for public in (
            '{"note":"' + escaped + '"}',
            '{"' + escaped + '":"public note"}',
            '["public note", {"nested":["' + escaped + '"]}]',
            '{"note":"' + escaped + '","note":"public replacement"}',
            '{"note":"public replacement","note":"' + escaped + '"}',
        ):
            with self.subTest(public=public):
                self.assert_refused(lambda: HostProtectedData.compile({"private": private, "public": source(public)}),
                                    "protected_data_cross_resource_disclosure")
        prices = {"private": source("内部底价162000元。"),
                  "public": source('{"note":"16.2\\u4e07\\u5143"}')}
        self.assert_refused(lambda: HostProtectedData.compile(prices), "protected_data_cross_resource_disclosure")
        public = source('{"note":"synthetic\\u002dpublic","note":["公开价198000元",null,true,17]}')
        data = HostProtectedData.compile({"private": private, "public": public})
        self.assertEqual(public.text, data.redacted("public", public.sha256))

    def test_numeric_identifiers_and_other_resource_prices_are_not_substrings(self):
        resources = {"private": source("内部底价162000元。"),
                     "public": source("公开报价198000元，编号A162000，批量合计1620000元。")}
        data = HostProtectedData.compile(resources)
        for text in ("198000元", "订单A162000", "1620000元", "/orders/162000", "2026-09-12"):
            with self.subTest(text=text):
                self.assertEqual((), data.match_output(text))
        for text in ("162,000元", "１６２０００元", "16.2万元"):
            with self.subTest(text=text):
                self.assertTrue(data.match_output(text))

    def test_utf8_source_ranges_and_json_quoted_fragments_are_privately_bound(self):
        resources = {"json": source('{"说明":"中文😀","password":"synthetic\\u002dquoted","内部底价":162000}')}
        data = HostProtectedData.compile(resources)
        row = json.loads(data.to_private_json())["resources"][0]
        original = resources["json"].text
        for item in row["fields"]:
            fragment = original[item["source_start"]:item["source_end"]]
            raw_fragment = original.encode()[item["source_byte_start"]:item["source_byte_end"]]
            self.assertEqual(fragment, item["source_fragment"])
            self.assertEqual(fragment.encode(), raw_fragment)
            self.assertEqual(hashlib.sha256(raw_fragment).hexdigest(), item["source_sha256"])
        self.assertEqual("synthetic-quoted", row["fields"][0]["value"])
        self.assertTrue(row["fields"][0]["source_fragment"].startswith('"'))
        self.assertNotIn("synthetic-quoted", repr(data))
        json.loads(data.redacted("json", resources["json"].sha256))

    def test_original_mapping_and_public_summary_mutations_do_not_change_snapshot(self):
        before = self.data.to_private_json()
        quote = self.resources["quote"]
        self.resources.clear()
        summary = self.data.public_summary()
        summary["field_count"] = 0
        self.assertEqual(before, self.data.to_private_json())
        self.assertTrue(self.data.match_output("162000元"))
        self.assertNotIn("162000", self.data.redacted("quote", quote.sha256))
        with self.assertRaises(FrozenInstanceError):
            quote.text = "modified"
        with self.assertRaises(FrozenInstanceError):
            self.data._values = ()
        self.assert_refused(HostProtectedData, "protected_data_compile_required")

    def test_resource_requests_types_sources_and_limits_fail_without_values(self):
        self.assert_refused(lambda: self.data.redacted("162000", "0" * 64), "protected_resource_missing")
        self.assert_refused(lambda: self.data.redacted("quote", "0" * 64), "protected_resource_changed")
        for digest in (None, "synthetic-api-ABC-123", "A" * 64):
            self.assert_refused(lambda: self.data.redacted("quote", digest), "invalid_protected_resource_request")
        for resources in (None, [], {"quote": {"text": "内部底价162000", "sha256": "0" * 64}},
                          {"bad\nname": source("public")}, {"bad\ud800name": source("public")}):
            self.assert_refused(lambda: HostProtectedData.compile(resources))
        self.assert_refused(lambda: HostResource("\ud800", "0" * 64), "invalid_host_resource")
        self.assert_refused(lambda: source("x" * (MAX_RESOURCE_BYTES + 1)), "invalid_host_resource")
        self.assert_refused(lambda: HostProtectedData.compile({"bad": source("内部底价：???")}))
        self.assert_refused(lambda: self.data.match_output(None), "protected_data_match_failed")
        empty = HostProtectedData.compile({})
        self.assert_refused(lambda: empty.match_output(None), "protected_data_match_failed")

    def test_total_field_limit_is_global_and_never_truncated_per_resource(self):
        resources = {f"resource-{index:02d}": source(f"password: synthetic-secret-{index:03d}") for index in range(65)}
        self.assert_refused(lambda: HostProtectedData.compile(resources), "protected_data_match_failed")


if __name__ == "__main__":
    unittest.main()
