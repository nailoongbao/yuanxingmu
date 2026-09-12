"""Host storage/validation tests; no model or network service is involved."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu import judge_profile as storage


class JudgeConfigurationTests(unittest.TestCase):
    def test_host_configuration_defaults_without_mutating_input(self):
        value = {"url": "http://127.0.0.1:8888/v1", "id": "local-judge"}
        normalized = storage.normalize_judge_config(value)
        self.assertEqual(value, {"url": "http://127.0.0.1:8888/v1", "id": "local-judge"})
        self.assertEqual(normalized, {**value, "api_key": "", "timeout_seconds": 30})
        self.assertEqual(storage.save_judge_profile(Path("not-created"), None), [])

    def test_only_https_or_literal_http_loopback_are_accepted(self):
        for url in ("https://api.example.test/v1", "http://127.0.0.1:8888/v1", "http://[::1]:8888/v1"):
            with self.subTest(url=url):
                self.assertEqual(storage.normalize_judge_config({"url": url, "id": "judge"})["url"], url)
        bad = ["http://localhost:8888/v1", "http://example.test/v1", "http://127.1/v1",
               "http://127.0.0.1.evil.test/v1", "http://192.0.2.1/v1", "ftp://example.test/v1",
               "https://user:password@example.test/v1", "https://example.test/v1?api_key=x",
               "https://example.test/v1#fragment", "https://example.test:70000/v1",
               "http://[::1%25eth0]/v1", "https://example.test/\nheader", "https://example.test\\@elsewhere/v1"]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ValueError):
                storage.normalize_judge_config({"url": url, "id": "judge"})

    def test_unknown_fields_missing_fields_keys_and_timeout_budget_fail_closed(self):
        base = {"url": "https://api.example.test/v1", "id": "judge"}
        cases = [[], {}, {"url": base["url"]}, {"id": "judge"}, {**base, "key_path": "../../model-key"},
                 {**base, "api_key": "secret\r\nheader"}, {**base, "api_key": None}, {**base, "id": ""},
                 {**base, "model_id": "extra"}, {**base, "url": None}]
        cases += [{**base, "timeout_seconds": value} for value in (0, -1, 45.01, 120, True, "30", None, float("nan"), float("inf"))]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                storage.normalize_judge_config(value)
        self.assertEqual(storage.normalize_judge_config({**base, "timeout_seconds": 45})["timeout_seconds"], 45)
        self.assertEqual(storage.normalize_judge_config({**base, "timeout_seconds": .5})["timeout_seconds"], .5)


@unittest.skipUnless(sys.platform.startswith("linux"), "Protected profile storage uses Linux descriptor-relative I/O")
class JudgeProfileStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.profile = Path(self.temporary.name) / "profile"
        self.profile.mkdir(mode=0o700)
        self.agent = {"url": "http://127.0.0.1:8899/v1", "id": "working-model"}
        self.config = {"url": "https://judge.example.test/v1", "id": "independent-judge",
                       "api_key": "HOST-ONLY-JUDGE-CREDENTIAL", "timeout_seconds": 42}

    def put(self, name, raw):
        path = self.profile / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def pins(self):
        return {name: hashlib.sha256((self.profile / name).read_bytes()).hexdigest()
                for name in (storage.CONFIG_NAME, storage.KEY_NAME)}

    def saved(self):
        storage.save_judge_profile(self.profile, self.config)
        return self.pins()

    def test_separate_private_files_and_complete_pins_round_trip(self):
        paths = storage.save_judge_profile(self.profile, self.config)
        self.assertEqual(paths, [self.profile / storage.CONFIG_NAME, self.profile / storage.KEY_NAME])
        public = json.loads(paths[0].read_bytes())
        self.assertEqual(public, {key: self.config[key] for key in ("url", "id", "timeout_seconds")})
        self.assertNotIn(self.config["api_key"], paths[0].read_text())
        self.assertEqual(paths[1].read_text(), self.config["api_key"])
        for path in paths:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        pins = {**self.pins(), "unrelated/fixed-file": "f" * 64}
        judge = storage.validate_judge_profile(self.profile, pins)
        self.assertEqual((judge.model_url, judge.model_id, judge.api_key, judge.timeout_seconds),
                         (self.config["url"], self.config["id"], self.config["api_key"], 42))
        self.assertNotIn(self.config["api_key"], repr(judge))
        self.assertEqual(storage.load_judge_profile(self.profile, self.agent, pins=pins), judge)

    def test_initialization_without_pins_does_not_require_working_model_key(self):
        self.saved()
        self.assertFalse((self.profile / "model-key").exists())
        judge = storage.load_judge_profile(self.profile, self.agent)
        self.assertEqual(judge.model_id, "independent-judge")

    def test_no_independent_files_preserves_agent_source_key_and_timeout(self):
        self.put("model-key", b"ORIGINAL-WORKING-MODEL-KEY")
        before = sorted(path.name for path in self.profile.iterdir())
        self.assertIsNone(storage.validate_judge_profile(self.profile, {}))
        judge = storage.load_judge_profile(self.profile, self.agent, pins={})
        self.assertEqual((judge.model_url, judge.model_id, judge.api_key, judge.timeout_seconds),
                         (self.agent["url"], self.agent["id"], "ORIGINAL-WORKING-MODEL-KEY", 30))
        report = storage.judge_profile_report(self.profile, self.agent, pins={})
        self.assertEqual(report, {"independent": False, "source": "agent", **self.agent, "timeout_seconds": 30})
        self.assertEqual(sorted(path.name for path in self.profile.iterdir()), before)

    def test_each_configuration_field_is_pinned(self):
        pins = self.saved()
        path = self.profile / storage.CONFIG_NAME
        original = path.read_bytes()
        for field, value in (("url", "https://other.example.test/v1"), ("id", "other-judge"), ("timeout_seconds", 43)):
            changed = json.loads(original)
            changed[field] = value
            path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "file_changed"):
                storage.load_judge_profile(self.profile, self.agent, pins=pins)
            path.write_bytes(original)

    def test_key_is_pinned_independently_of_public_configuration(self):
        pins = self.saved()
        self.put(storage.KEY_NAME, b"REPLACEMENT-HOST-CREDENTIAL")
        with self.assertRaisesRegex(ValueError, "file_changed"):
            storage.load_judge_profile(self.profile, self.agent, pins=pins)

    def test_existing_profile_rejects_unpinned_or_partially_pinned_pair(self):
        pins = self.saved()
        for candidate in ({}, {storage.CONFIG_NAME: pins[storage.CONFIG_NAME]},
                          {storage.KEY_NAME: pins[storage.KEY_NAME]},
                          {**pins, storage.KEY_NAME: "not-a-digest"},
                          {**pins, storage.KEY_NAME: None},
                          {"../judge-config.json": pins[storage.CONFIG_NAME], storage.KEY_NAME: pins[storage.KEY_NAME]}, []):
            with self.subTest(pins=candidate), self.assertRaises(ValueError):
                storage.load_judge_profile(self.profile, self.agent, pins=candidate)

    def test_pinned_pair_cannot_be_removed_to_fall_back(self):
        pins = self.saved()
        for name in (storage.CONFIG_NAME, storage.KEY_NAME):
            (self.profile / name).unlink()
        self.put("model-key", b"AGENT-KEY")
        with self.assertRaisesRegex(ValueError, "file_missing"):
            storage.load_judge_profile(self.profile, self.agent, pins=pins)

    def test_partial_pair_never_falls_back(self):
        self.put("model-key", b"AGENT-KEY")
        for name in (storage.CONFIG_NAME, storage.KEY_NAME):
            path = self.put(name, b"partial")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "incomplete"):
                storage.load_judge_profile(self.profile, self.agent)
            path.unlink()

    def test_files_cannot_be_overwritten(self):
        pins = self.saved()
        with self.assertRaisesRegex(ValueError, "already_exists"):
            storage.save_judge_profile(self.profile, {**self.config, "id": "replacement"})
        self.assertEqual(self.pins(), pins)

    def test_disk_configuration_cannot_inject_paths_extra_keys_or_json_duplicates(self):
        self.saved()
        public = {key: self.config[key] for key in ("url", "id", "timeout_seconds")}
        cases = [json.dumps({**public, "api_key": "in-config"}).encode(),
                 json.dumps({**public, "key_file": "../../model-key"}).encode(),
                 b'{"url":"https://first.example/v1","url":"https://second.example/v1","id":"judge","timeout_seconds":30}',
                 b'{"url":"https://example.test/v1","id":"judge","timeout_seconds":NaN}',
                 b'[]', b'{"url":"https://example.test/v1","id":"judge"}', b'\xff']
        for raw in cases:
            self.put(storage.CONFIG_NAME, raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                storage.load_judge_profile(self.profile, self.agent, pins=self.pins())

    def test_oversized_config_key_and_invalid_key_text_are_rejected(self):
        self.saved()
        originals = {name: (self.profile / name).read_bytes() for name in (storage.CONFIG_NAME, storage.KEY_NAME)}
        for name, raw in ((storage.CONFIG_NAME, b" " * 8193), (storage.KEY_NAME, b"x" * 16385),
                          (storage.KEY_NAME, b"\xff"), (storage.KEY_NAME, b"secret\nheader")):
            self.put(name, raw)
            with self.subTest(name=name, size=len(raw)), self.assertRaises(ValueError):
                storage.load_judge_profile(self.profile, self.agent, pins=self.pins())
            self.put(name, originals[name])

    def test_symlink_dangling_symlink_and_hardlink_files_are_rejected(self):
        self.saved()
        external = Path(self.temporary.name) / "external"
        external.write_bytes(b"HOST-ONLY-JUDGE-CREDENTIAL")
        external.chmod(0o600)
        key = self.profile / storage.KEY_NAME
        for kind in ("symlink", "dangling", "hardlink"):
            key.unlink()
            if kind == "hardlink":
                os.link(external, key)
            else:
                key.symlink_to(external if kind == "symlink" else external.with_name("missing"))
            with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)):
                storage.load_judge_profile(self.profile, self.agent)
        self.assertEqual(external.read_bytes(), b"HOST-ONLY-JUDGE-CREDENTIAL")

    def test_profile_and_parent_symlink_or_traversal_are_rejected(self):
        self.saved()
        link = Path(self.temporary.name) / "link"
        link.symlink_to(self.profile, target_is_directory=True)
        parent_link = Path(self.temporary.name) / "parent-link"
        parent_link.symlink_to(Path(self.temporary.name), target_is_directory=True)
        bad = [link, parent_link / "profile", self.profile / ".." / "profile", Path("relative/profile"), Path("/")]
        for path in bad:
            with self.subTest(path=str(path)), self.assertRaises((OSError, ValueError)):
                storage.validate_judge_profile(path)

    def test_special_files_cannot_block_read_or_masquerade_as_key(self):
        self.saved()
        key = self.profile / storage.KEY_NAME
        key.unlink()
        os.mkfifo(key, mode=0o600)
        with self.assertRaisesRegex(ValueError, "invalid_judge_profile_file"):
            storage.load_judge_profile(self.profile, self.agent)

    def test_publicly_readable_key_and_writable_profile_are_rejected(self):
        self.saved()
        key = self.profile / storage.KEY_NAME
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "invalid_judge_profile_file"):
            storage.validate_judge_profile(self.profile)
        key.chmod(0o600)
        self.profile.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "directory_not_host_owned"):
            storage.validate_judge_profile(self.profile)
        self.profile.chmod(0o700)

    def test_concurrent_creates_have_exactly_one_winner_without_overwrite(self):
        barrier = threading.Barrier(2)

        def save(identifier):
            barrier.wait()
            try:
                storage.save_judge_profile(self.profile, {**self.config, "id": identifier, "api_key": identifier + "-key"})
                return identifier
            except (OSError, ValueError):
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, ["first", "second"]))
        winners = [value for value in results if value is not None]
        self.assertEqual(len(winners), 1)
        judge = storage.validate_judge_profile(self.profile, self.pins())
        self.assertEqual((judge.model_id, judge.api_key), (winners[0], winners[0] + "-key"))

    def test_partial_write_failure_stays_unloadable(self):
        original = storage._write

        def fail_config(directory, name, content):
            if name == storage.CONFIG_NAME:
                raise OSError("simulated disk failure")
            return original(directory, name, content)

        with patch.object(storage, "_write", side_effect=fail_config):
            with self.assertRaises(OSError):
                storage.save_judge_profile(self.profile, self.config)
        self.put("model-key", b"AGENT-KEY")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            storage.load_judge_profile(self.profile, self.agent)
        with self.assertRaisesRegex(ValueError, "already_exists"):
            storage.save_judge_profile(self.profile, self.config)

    def test_changed_file_during_read_is_rejected_without_using_unpinned_bytes(self):
        pins = self.saved()
        original = storage.os.read
        changed = False

        def mutate_after_first_read(descriptor, maximum):
            nonlocal changed
            data = original(descriptor, maximum)
            if data and not changed:
                changed = True
                with (self.profile / storage.CONFIG_NAME).open("ab") as stream:
                    stream.write(b" ")
            return data

        with patch.object(storage.os, "read", side_effect=mutate_after_first_read):
            with self.assertRaisesRegex(ValueError, "file_changed"):
                storage.validate_judge_profile(self.profile, pins)

    def test_report_is_allowlisted_read_only_and_never_returns_credentials(self):
        pins = self.saved()
        before = {name: ((self.profile / name).read_bytes(), (self.profile / name).stat().st_mtime_ns)
                  for name in (storage.CONFIG_NAME, storage.KEY_NAME)}
        report = storage.judge_profile_report(self.profile, self.agent, pins=pins)
        self.assertEqual(report, {"independent": True, "source": "independent", "url": self.config["url"],
                                  "id": self.config["id"], "timeout_seconds": 42})
        encoded = json.dumps(report)
        self.assertNotIn(self.config["api_key"], encoded)
        self.assertNotIn(pins[storage.KEY_NAME], encoded)
        self.assertNotIn(str(self.profile), encoded)
        for name, value in before.items():
            self.assertEqual(((self.profile / name).read_bytes(), (self.profile / name).stat().st_mtime_ns), value)

    def test_report_redacts_key_accidentally_pasted_into_display_fields(self):
        storage.save_judge_profile(self.profile, {**self.config, "id": "judge-" + self.config["api_key"],
                                                  "url": self.config["url"] + "/" + self.config["api_key"]})
        report = storage.judge_profile_report(self.profile, self.agent, pins=self.pins())
        self.assertNotIn(self.config["api_key"], json.dumps(report))
        self.assertIn("[已隐藏]", report["id"])

    def test_save_load_validate_and_report_never_make_network_calls(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("http.client.HTTPConnection", side_effect=AssertionError("network forbidden")), \
                patch("http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")):
            pins = self.saved()
            storage.load_judge_profile(self.profile, self.agent, pins=pins)
            storage.validate_judge_profile(self.profile, pins)
            storage.judge_profile_report(self.profile, self.agent, pins=pins)


if __name__ == "__main__":
    unittest.main()
