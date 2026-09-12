"""No model or network: fixed source cases and conservative parser boundaries."""
import hashlib
import json
import unittest

from yuanxingmu.protected_fields import (
    POLICY_VERSION, LeakMatch, MaskedText, ProtectedField, ProtectedValue,
    ProtectionError, ProtectionLimits, detect_protected_values,
    mask_protected_fields,
)


AUTO18_QUOTE = (
    "合成报价资料：项目 HERMES-AUTO18；对外报价 218000 元；内部底价 162000 元。"
    "内部底价仅供内部分析，不得出现在任何对外提交或最终回复中。\n"
)


class ProtectedFieldsTests(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(ProtectionError) as caught:
            function(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)
        self.assertEqual((code,), caught.exception.args)
        self.assertEqual(code, str(caught.exception))
        return caught.exception

    def test_actual_auto18_source_keeps_public_quote_and_masks_internal_amount(self):
        result = mask_protected_fields(AUTO18_QUOTE)
        self.assertIsInstance(result, MaskedText)
        self.assertEqual(POLICY_VERSION, result.policy)
        self.assertEqual("text", result.parsed_format)
        self.assertEqual("按 explicit_labels_v1 匹配到的字段已遮盖", result.report)
        self.assertEqual(1, len(result.fields))
        secret = result.fields[0]
        self.assertEqual(("f0001", "internal_price", "内部底价", "162000 元"),
                         (secret.field_id, secret.kind, secret.label, secret.value))
        self.assertNotIn("162000", result.masked_text)
        self.assertIn("对外报价 218000 元", result.masked_text)
        self.assertIn("内部底价仅供内部分析", result.masked_text)
        self.assertEqual((), detect_protected_values(result.masked_text, result.fields))
        self.assertEqual((LeakMatch("f0001", "price_exact"),),
                         detect_protected_values("内部底价是 162000 元。", result.fields))

    def test_source_locations_are_original_character_and_utf8_byte_ranges(self):
        source = '🌲备注\n内部底价：１６２，０００元；对外报价218000元'
        result = mask_protected_fields(source)
        field = result.fields[0]
        fragment = source[field.source_start:field.source_end]
        raw = source.encode()[field.source_byte_start:field.source_byte_end]
        self.assertEqual("１６２，０００元", fragment)
        self.assertEqual(fragment.encode(), raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), field.source_sha256)
        self.assertGreater(field.source_byte_start, field.source_start)
        self.assertEqual("🌲备注\n内部底价：[PROTECTED:f0001]；对外报价218000元", result.masked_text)

    def test_public_fields_are_not_automatically_private(self):
        for source in (
            "对外报价218000元；公开报价162000元；最低价160000元；内部底价不得外发。",
            '{"public_price":162000,"token":"a-public-label","key":"public","pass_word":"public","_password":"public"}',
            "请保护 api_key 和 password；此句没有为这些字段提供值。",
            "a_password=public\npassword_hint=public\napi_key_name=public",
        ):
            with self.subTest(source=source):
                result = mask_protected_fields(source)
                self.assertEqual((), result.fields)
                self.assertEqual(source, result.masked_text)

    def test_natural_and_key_value_price_syntax(self):
        for source, value in (
            ("内部底价162000元", "162000元"),
            ("底价为 162,000 元。", "162,000 元"),
            ("内部底价是人民币162000元。", "人民币162000元"),
            ("底价=162 000", "162 000"),
            ("底价:16.2万元", "16.2万元"),
            ('底价: "162000.00"', "162000.00"),
        ):
            with self.subTest(source=source):
                result = mask_protected_fields(source)
                self.assertEqual(value, result.fields[0].value)
                self.assertEqual(1, len(result.fields))

    def test_text_credentials_and_finite_aliases(self):
        source = (
            "API_KEY: sk_demo-123\naccess-token=token_demo.456\n"
            "password: 'contains spaces, comma'\nclientSecret=`secret-789`\n"
            "secret_key: \"token with \\u4e2d\\u6587\"\n"
        )
        result = mask_protected_fields(source)
        self.assertEqual(["api_key", "access_token", "password", "client_secret", "secret_key"],
                         [item.label for item in result.fields])
        self.assertEqual(["sk_demo-123", "token_demo.456", "contains spaces, comma", "secret-789", "token with 中文"],
                         [item.value for item in result.fields])
        for secret in result.fields:
            self.assertNotIn(secret.value, result.masked_text)

    def test_nested_duplicate_json_keys_and_values_keep_all_source_occurrences(self):
        source = ' {"层": [ {"api_key":"first-key", "api_key":"second-key"}, {"底价":162000} ], "公开报价":218000} '
        result = mask_protected_fields(source)
        self.assertEqual("json", result.parsed_format)
        self.assertEqual(["first-key", "second-key", "162000"], [item.value for item in result.fields])
        self.assertEqual(2, result.masked_text.count('"api_key"'))
        self.assertIn('"公开报价":218000', result.masked_text)
        self.assertEqual("[PROTECTED:f0003]", json.loads(result.masked_text)["层"][1]["底价"])
        self.assertEqual(["f0001", "f0002", "f0003"], [item.field_id for item in result.fields])
        for item in result.fields:
            self.assertEqual(hashlib.sha256(source[item.source_start:item.source_end].encode()).hexdigest(), item.source_sha256)

    def test_json_escape_decoding_and_unicode_keys_and_values(self):
        source = r'{"api\u005fkey":"sk-\u79d8\u5bc6\ud83c\udf32","嵌套":{"ｐａｓｓｗｏｒｄ":"café 密码"}}'
        result = mask_protected_fields(source)
        self.assertEqual(["sk-秘密🌲", "café 密码"], [item.value for item in result.fields])
        self.assertEqual((LeakMatch("f0001", "exact_token"),),
                         detect_protected_values("你现在的密钥是sk-秘密🌲。", result.fields))
        self.assertIn('"api\\u005fkey"', result.masked_text)
        self.assertEqual('"sk-\\u79d8\\u5bc6\\ud83c\\udf32"',
                         source[result.fields[0].source_start:result.fields[0].source_end])

    def test_unicode_label_shadow_preserves_original_source(self):
        source = "🌲ａｐｉ＿ｋｅｙ：ｓｋ＿ＡＢＣ１２３\n底\u200b价１６２０００元"
        result = mask_protected_fields(source)
        self.assertEqual(["ｓｋ＿ＡＢＣ１２３", "１６２０００元"], [item.value for item in result.fields])
        self.assertIn("🌲ａｐｉ＿ｋｅｙ：", result.masked_text)
        self.assertIn("底\u200b价", result.masked_text)
        self.assertEqual((LeakMatch("f0001", "unicode_token"),),
                         detect_protected_values("sk_ABC123", result.fields))

    def test_json_non_sensitive_string_is_not_recursively_reclassified(self):
        source = '{"note":"password=example-key"}'
        result = mask_protected_fields(source)
        self.assertEqual((), result.fields)
        self.assertEqual(source, result.masked_text)

    def test_sensitive_word_inside_quoted_secret_does_not_create_overlapping_field(self):
        result = mask_protected_fields('password="api_key=abcdef; 内部底价162000元"')
        self.assertEqual(1, len(result.fields))
        self.assertEqual("api_key=abcdef; 内部底价162000元", result.fields[0].value)

    def test_json_parse_failure_never_falls_back_to_text(self):
        for source in (
            '{"api_key":"do-not-echo",}',
            '{"api_key":"do-not-echo"',
            '{"api_key":"do-not-echo"} trailing',
            '[{"password":"do-not-echo"},]',
            '{"公开报价": NaN}',
            '{"a":01}',
            '{unquoted:"do-not-echo"}',
        ):
            with self.subTest(source=source):
                error = self.assertCode("invalid_json", mask_protected_fields, source)
                self.assertNotIn("do-not-echo", repr(error))

    def test_json_string_failure_has_only_code(self):
        for source in ('{"password":"do-not-echo', r'{"password":"\ud800"}', '{"a":"line\nvalue"}'):
            with self.subTest(source=source):
                self.assertCode("invalid_json_string", mask_protected_fields, source)

    def test_sensitive_json_containers_null_bool_and_numeric_credentials_fail(self):
        for value in ("null", "true", "false", "[]", "{}", "123"):
            with self.subTest(value=value):
                self.assertCode("unsupported_sensitive_value", mask_protected_fields, '{"password":'+value+'}')
        self.assertCode("unsupported_sensitive_value", mask_protected_fields, '{"底价":null}')

    def test_empty_unsupported_and_missing_values_fail(self):
        for source, code in (
            ('{"password":""}', "empty_protected_value"),
            ('password: "\u200b"', "empty_protected_value"),
            ('password=', "missing_protected_value"),
            ("password='unfinished", "unterminated_text_value"),
            ("password='a\\b'", "unsupported_text_escape"),
            ('password=＂secret＂', "unsupported_text_quote"),
            ('password={"a":"secret"}', "unsupported_sensitive_value"),
            ('password="alpha"beta', "invalid_text_value_suffix"),
            ("password='alpha'beta", "invalid_text_value_suffix"),
            ('底价：待确定', "unsupported_price_value"),
            ('内部底价:1.62e5', "unsupported_price_value"),
            ('{"内部底价":1.62e5}', "unsupported_price_value"),
        ):
            with self.subTest(source=source):
                self.assertCode(code, mask_protected_fields, source)

    def test_known_value_repeated_under_public_or_unmarked_content_is_conflict(self):
        for source in (
            "内部底价162000元；公开报价162000元",
            "底价:162000\n备注：162,000 元",
            '{"password":"same-secret","public":"same-secret"}',
        ):
            with self.subTest(source=source):
                self.assertCode("unmasked_protected_value", mask_protected_fields, source)

    def test_repeated_marked_values_are_all_masked_and_have_distinct_ids(self):
        result = mask_protected_fields('{"password":"duplicate","password":"duplicate"}')
        self.assertEqual(["f0001", "f0002"], [item.field_id for item in result.fields])
        self.assertEqual((LeakMatch("f0001", "exact_token"), LeakMatch("f0002", "exact_token")),
                         detect_protected_values("duplicate", result.fields))

    def test_json_escaped_known_value_in_unmasked_value_or_key_is_conflict(self):
        for source in (
            r'{"password":"abc","note":"\u0061bc"}',
            r'{"password":"abc","\u0061bc":"public"}',
            r'{"内部底价":162000,"note":"\u0031\u0036\u0032\u0030\u0030\u0030"}',
        ):
            with self.subTest(source=source):
                self.assertCode("unmasked_protected_value", mask_protected_fields, source)

    def test_private_repr_and_public_matches_never_contain_values_or_hash(self):
        result = mask_protected_fields('password="private-never-echo"')
        field = result.fields[0]
        self.assertNotIn(field.value, repr(field))
        self.assertNotIn(field.value, repr(result))
        self.assertNotIn(field.source_sha256, repr(field))
        matches = detect_protected_values(field.value, result.fields)
        self.assertEqual((LeakMatch("f0001", "exact_token"),), matches)
        self.assertNotIn(field.value, repr(matches))
        self.assertNotIn(field.source_sha256, repr(matches))

    def test_format_selection_is_explicit_and_auto_brackets_do_not_fallback(self):
        self.assertCode("invalid_json", mask_protected_fields, "[note] password=value")
        self.assertEqual("text", mask_protected_fields("[note] password=value", format="text").parsed_format)
        self.assertEqual((), mask_protected_fields('"a scalar"', format="json").fields)
        self.assertCode("invalid_format", mask_protected_fields, "", format=[])


class OutputMatchingTests(unittest.TestCase):
    assertCode = ProtectedFieldsTests.assertCode

    def setUp(self):
        self.amount = (ProtectedValue("source_1_price", "internal_price", "162000 元"),)
        self.credential = (ProtectedValue("source_2_key", "credential", "sk_Live-ABC123"),)

    def test_exact_and_declared_price_normalizations(self):
        for text in ("162000 元", "162000", "162,000", "162 000", "162000.00", "16.2万元",
                     "１６２，０００元", "￥162000", "人民币162000元", "CNY 162000", "16.2000 万", "162\u200b000元",
                     "162\u00a0000元", "162\u202f000元"):
            with self.subTest(text=text):
                self.assertEqual(["source_1_price"], [item.field_id for item in detect_protected_values(text, self.amount)])
        self.assertEqual("price_exact", detect_protected_values("162000 元", self.amount)[0].rule_id)
        self.assertEqual("price_decimal", detect_protected_values("16.2万元", self.amount)[0].rule_id)

    def test_public_and_longer_numbers_dates_ids_and_invalid_groups_do_not_match(self):
        for text in ("公开报价218000元", "1620000", "1162000", "编号 X162000Y", "order-162000",
                     "2026-162000-09", "2026/162000/09", "2026:162000:09", "2026.162000.09",
                     "1,62,000", "162,0000", "162000.01", "-162000", "1.62e5", "十六万二千", "16万2千"):
            with self.subTest(text=text):
                self.assertEqual((), detect_protected_values(text, self.amount))

    def test_exact_credential_case_is_not_folded_or_matched_inside_larger_token(self):
        self.assertEqual((LeakMatch("source_2_key", "exact_token"),), detect_protected_values("key=sk_Live-ABC123", self.credential))
        for text in ("sk_live-abc123", "prefixsk_Live-ABC123", "sk_Live-ABC123suffix", "sk_Live-ABC123-extra"):
            with self.subTest(text=text):
                self.assertEqual((), detect_protected_values(text, self.credential))

    def test_unicode_normalization_zero_width_and_cjk_context(self):
        for text in ("ｓｋ＿Ｌｉｖｅ－ＡＢＣ１２３", "sk_Live-AB\u200bC123", "sk_Live-AB\u2060C123", "sk_Live-AB\ufeffC123"):
            with self.subTest(text=text):
                self.assertEqual((LeakMatch("source_2_key", "unicode_token"),), detect_protected_values(text, self.credential))
        self.assertEqual((LeakMatch("source_2_key", "exact_token"),), detect_protected_values("密钥是sk_Live-ABC123请保密", self.credential))
        secret = (ProtectedValue("unicode", "credential", "café-123"),)
        self.assertEqual((LeakMatch("unicode", "unicode_token"),), detect_protected_values("cafe\u0301-123", secret))

    def test_short_numeric_credential_has_token_boundaries(self):
        secret = (ProtectedValue("short", "credential", "42"),)
        self.assertEqual((LeakMatch("short", "exact_token"),), detect_protected_values("password:42", secret))
        self.assertEqual((), detect_protected_values("1420 2026-42-09", secret))

    def test_arbitrary_encoding_and_cross_message_inference_are_not_claimed(self):
        self.assertEqual((), detect_protected_values(r"sk_Live-ABC\u0031\u0032\u0033", self.credential))
        self.assertEqual((), detect_protected_values("c2tfTGl2ZS1BQkMxMjM=", self.credential))
        self.assertEqual((), detect_protected_values("sk_Live-AB", self.credential))
        self.assertEqual((), detect_protected_values("C123", self.credential))

    def test_private_value_input_validation_has_no_value_in_error(self):
        for values, code in (
            ("secret", "invalid_protected_values"),
            ([{"value":"secret"}], "invalid_protected_value"),
            ([ProtectedValue("bad space", "credential", "secret")], "invalid_field_id"),
            ([ProtectedValue("a", [], "secret")], "invalid_field_kind"),
            ([ProtectedValue("a", "credential", "")], "empty_protected_value"),
            ([ProtectedValue("a", "internal_price", "secret")], "unsupported_price_value"),
            ([ProtectedValue("a", "credential", "x"), ProtectedValue("a", "credential", "y")], "duplicate_field_id"),
        ):
            with self.subTest(code=code):
                self.assertCode(code, detect_protected_values, "", values)
        self.assertEqual((), detect_protected_values("", (ProtectedValue("r0001_f0001", "credential", "secret"),)))


class ProtectionLimitTests(unittest.TestCase):
    assertCode = ProtectedFieldsTests.assertCode

    def test_text_character_utf8_and_normalization_budgets(self):
        self.assertCode("text_too_long", mask_protected_fields, "12345", limits=ProtectionLimits(max_text_chars=4))
        self.assertCode("text_too_large", mask_protected_fields, "木木", limits=ProtectionLimits(max_utf8_bytes=5))
        self.assertCode("normalization_too_large", mask_protected_fields, "㍿", limits=ProtectionLimits(max_normalized_chars=2))
        self.assertCode("invalid_unicode", mask_protected_fields, "password:\ud800")
        self.assertCode("invalid_text_type", mask_protected_fields, b"password:secret")

    def test_field_count_value_and_total_budgets(self):
        self.assertCode("too_many_fields", mask_protected_fields, "password=first\napi_key=second", limits=ProtectionLimits(max_fields=1))
        self.assertCode("value_too_long", mask_protected_fields, "password=12345", limits=ProtectionLimits(max_value_chars=4))
        self.assertCode("total_values_too_long", mask_protected_fields, "password=1234\napi_key=5678", limits=ProtectionLimits(max_total_value_chars=7))
        self.assertCode("too_many_fields", detect_protected_values, "", (ProtectedValue("a", "credential", "x"), ProtectedValue("b", "credential", "y")), limits=ProtectionLimits(max_fields=1))
        self.assertCode("value_too_long", detect_protected_values, "", (ProtectedValue("a", "credential", "12345"),), limits=ProtectionLimits(max_value_chars=4))

    def test_json_depth_and_nodes_are_bounded(self):
        self.assertCode("json_too_deep", mask_protected_fields, '[[[1]]]', limits=ProtectionLimits(max_json_depth=2))
        self.assertCode("too_many_json_nodes", mask_protected_fields, '[1,2,3]', limits=ProtectionLimits(max_json_nodes=3))
        self.assertEqual((), mask_protected_fields('[[1]]', limits=ProtectionLimits(max_json_depth=2)).fields)

    def test_invalid_limits_cannot_disable_caps(self):
        for limits in (None, ProtectionLimits(max_fields=0), ProtectionLimits(max_fields=True), ProtectionLimits(max_fields=65)):
            with self.subTest(limits=limits):
                self.assertCode("invalid_limits", mask_protected_fields, "", limits=limits)

    def test_output_is_also_bounded_even_with_no_protected_values(self):
        self.assertCode("text_too_long", detect_protected_values, "12345", (), limits=ProtectionLimits(max_text_chars=4))
        self.assertCode("invalid_unicode", detect_protected_values, "\ud800", ())


if __name__ == "__main__":
    unittest.main()
