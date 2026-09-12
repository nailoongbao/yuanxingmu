from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from yuanxingmu.actions import Actions, ActionTarget, MAX_CONTENT_BYTES, validate_proposal
from yuanxingmu.authority import Authority, AuthorizationError


class Receiver:
    def __init__(self):
        self.received = []
        self.callback = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                fixture.received.append({"path": self.path, "headers": dict(self.headers), "data": data})
                if fixture.callback:
                    fixture.callback()
                if self.path == "/lost":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                status, body = 200, b'{"accepted":true}'
                if self.path == "/slack":
                    body = b"ok"
                elif self.path == "/feishu":
                    body = b'{"code":0}'
                elif self.path == "/feishu-error":
                    body = b'{"code":42,"msg":"provider rejected"}'
                elif self.path == "/redirect":
                    status = 302
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/must-not-follow")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class ActionsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.db_path = self.directory / "authority.sqlite3"
        self.authority = Authority(self.db_path)
        self.addCleanup(self.authority.close)
        self.task = self.authority.create_root({}, {}, initial_labels=["private"])
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)
        self.targets = {
            "chat": ActionTarget("message", "核对后的消息", port=self.receiver.port),
            "files": ActionTarget("upload", "资料接收端", port=self.receiver.port),
            "request": ActionTarget("form", "报名表", port=self.receiver.port, form_fields=("name", "note")),
        }
        self.store = Actions(self.authority, self.targets)

    def new(self, kind="message", target="chat", payload=None, key="request-1", store=None, task=None):
        proposal = {"kind": kind, "target_id": target, "payload": {"body": "私密草稿\n请核对"} if payload is None else payload}
        return (store or self.store).submit(task or self.task, key, proposal)

    def commit(self, row, store=None, task=None):
        return (store or self.store).commit(task or self.task, row["id"], row["revision"], row["digest"])

    def denied(self, reason, function, *args, **kwargs):
        with self.assertRaises(AuthorizationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(reason, caught.exception.reason)

    def files(self):
        if os.name != "posix":
            self.skipTest("Safe file actions require POSIX no-follow directory descriptors")
        root = self.directory / "host-files"
        root.mkdir(mode=0o700)
        (root / "report.txt").write_text("旧文件：私密内容\n", encoding="utf-8")
        (root / "discard.txt").write_text("待删除的完整内容", encoding="utf-8")
        self.targets.update({
            "report": ActionTarget("overwrite", "审核后的报告", workspace=root, relative_path="report.txt"),
            "discard": ActionTarget("delete", "已选中的待删除文件", workspace=root, relative_path="discard.txt"),
        })
        self.store = Actions(self.authority, self.targets)
        return root

    def test_three_real_transports_are_inert_until_review_and_execute_once(self):
        cases = [
            ("message", "chat", {"body": "精确消息\n第二行"}),
            ("upload", "files", {"filename": "report.txt", "content": "上传全文\n<&>"}),
            ("form", "request", {"fields": {"name": "李同学", "note": "A&B=具体内容"}}),
        ]
        rows = [self.new(kind, target, payload, key=f"request-{i}") for i, (kind, target, payload) in enumerate(cases)]
        self.assertEqual([], self.receiver.received)
        for row, (_, _, payload) in zip(rows, cases):
            self.assertEqual("pending", row["status"])
            self.assertNotIn("proposal", row)
            self.assertNotIn("before", row)
            reviewed = self.store.get(self.task, row["id"])["action"]
            self.assertEqual(payload, reviewed["proposal"]["payload"])
            sent = self.commit(row)
            self.assertTrue(sent["started"])
            self.assertEqual("acknowledged", sent["action"]["status"])
            replay = self.commit(row)
            self.assertFalse(replay["started"])
            self.assertEqual(sent["action"], replay["action"])
        self.assertEqual(3, len(self.receiver.received))
        message, upload, form = self.receiver.received
        self.assertEqual({"body": "精确消息\n第二行"}, json.loads(message["data"]))
        mime = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + upload["headers"]["Content-Type"].encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + upload["data"])
        part = list(mime.iter_parts())[0]
        self.assertEqual("report.txt", part.get_filename())
        self.assertEqual("上传全文\n<&>".encode(), part.get_payload(decode=True))
        self.assertEqual({"name": ["李同学"], "note": ["A&B=具体内容"]}, parse_qs(form["data"].decode("ascii")))
        self.assertEqual(["/message", "/upload", "/form"], [x["path"] for x in self.receiver.received])

    def test_provider_formats_and_semantic_acknowledgements(self):
        targets = {
            "text": ActionTarget("message", "通用文本", url=self.receiver.url("/text"), provider="text"),
            "slack": ActionTarget("message", "Slack 已配置频道", url=self.receiver.url("/slack"), provider="slack"),
            "feishu": ActionTarget("message", "飞书已配置群聊", url=self.receiver.url("/feishu"), provider="feishu"),
            "rejected": ActionTarget("message", "拒绝请求的测试端", url=self.receiver.url("/feishu-error"), provider="feishu"),
        }
        store = Actions(self.authority, targets)
        outcomes = []
        for target in targets:
            row = self.new(target=target, key=target, store=store)
            outcomes.append(self.commit(row, store)["action"]["status"])
        self.assertEqual(["acknowledged", "acknowledged", "acknowledged", "unconfirmed"], outcomes)
        self.assertEqual({"text": "私密草稿\n请核对"}, json.loads(self.receiver.received[0]["data"]))
        self.assertEqual({"text": "私密草稿\n请核对"}, json.loads(self.receiver.received[1]["data"]))
        self.assertEqual({"msg_type": "text", "content": {"text": "私密草稿\n请核对"}}, json.loads(self.receiver.received[2]["data"]))

    def test_edit_stales_confirmation_and_request_key_keeps_original_binding(self):
        original = self.new()
        proposal = {"kind": "message", "target_id": "chat", "payload": {"body": "用户核对后的内容"}}
        changed = self.store.edit(self.task, original["id"], original["revision"], original["digest"], proposal)
        self.assertEqual(2, changed["revision"])
        self.assertNotEqual(original["digest"], changed["digest"])
        self.denied("action_changed", self.commit, original)
        self.assertEqual(changed["digest"], self.new()["digest"])
        self.denied("action_request_conflict", self.store.submit, self.task, "request-1", proposal)
        self.assertEqual([], self.receiver.received)
        self.commit(changed)
        self.assertEqual({"body": "用户核对后的内容"}, json.loads(self.receiver.received[0]["data"]))

    def test_fixed_target_credentials_and_binding_survive_serialization_without_leaking(self):
        secret = "Bearer HOST-SECRET-DO-NOT-EXPOSE"
        target = ActionTarget("message", "已登记收件人", url=self.receiver.url("/message?host=selected"), headers={"Authorization": secret})
        restored = ActionTarget(**target.to_config())
        self.assertEqual(target.binding(), restored.binding())
        store = Actions(self.authority, {"chat": target})
        row = self.new(store=store)
        safe = json.dumps([row, store.get(self.task, row["id"]), store.describe_targets(), store.binding(), self.authority.events(self.task)])
        self.assertNotIn(secret, safe)
        self.assertNotIn("host=selected", safe)
        self.assertNotIn(secret, repr(target))
        with self.assertRaises(TypeError):
            target.headers["Authorization"] = "replacement"
        changed = Actions(self.authority, {"chat": ActionTarget("message", target.label, url=target.url, headers={"Authorization": "CHANGED"})})
        self.assertNotEqual(store.binding_digest(), changed.binding_digest())
        self.denied("action_target_changed", self.commit, row, store=changed)
        self.commit(row, store)
        self.assertEqual(secret, self.receiver.received[0]["headers"]["Authorization"])

    def test_revocation_and_task_identity_prevent_new_commits(self):
        row = self.new()
        other = self.authority.create_root({}, {})
        self.denied("action_not_found", self.commit, row, task=other)
        child = self.authority.delegate(self.task)
        child_row = self.new(task=child, key="child")
        self.authority.revoke(self.task)
        self.denied("task_revoked", self.commit, row)
        self.denied("task_revoked", self.commit, child_row, task=child)
        self.denied("task_revoked", self.new, key="revoked")
        self.assertFalse(self.store.get(self.task, row["id"])["active"])
        self.assertEqual([], self.receiver.received)

    def test_concurrent_confirmations_emit_one_request_and_persist_before_io(self):
        row = self.new()
        observed = []
        def observe():
            with Authority(self.db_path) as reader:
                result = Actions(reader, self.targets).get(self.task, row["id"])["action"]
                observed.append((result["status"], result["attempt_id"]))
        self.receiver.callback = observe
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.commit(row), range(6)))
        self.assertEqual(1, sum(x["started"] for x in results))
        self.assertEqual(1, len(self.receiver.received))
        self.assertEqual("executing", observed[0][0])
        self.assertEqual(results[0]["action"]["attempt_id"], observed[0][1])
        self.authority.revoke(self.task)
        self.assertFalse(self.commit(row)["started"])
        self.assertEqual(1, len(self.receiver.received))

    def test_lost_ack_and_redirect_never_trigger_automatic_retry(self):
        store = Actions(self.authority, {name: ActionTarget("message", name, url=self.receiver.url("/" + name)) for name in ("lost", "redirect")})
        for name in ("lost", "redirect"):
            row = self.new(target=name, key=name, store=store)
            result = self.commit(row, store)
            self.assertEqual("unconfirmed", result["action"]["status"])
            self.assertFalse(self.commit(row, store)["started"])
        self.assertEqual(["/lost", "/redirect"], [x["path"] for x in self.receiver.received])

    def test_connection_refusal_consumes_attempt_and_crash_recovery_is_read_only(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            store = Actions(self.authority, {"offline": ActionTarget("message", "未监听端口", port=port)})
            row = self.new(target="offline", key="offline", store=store)
            result = self.commit(row, store)
        self.assertEqual("not_started", result["action"]["status"])
        with patch("yuanxingmu.actions._perform_network", side_effect=AssertionError("must not retry")):
            self.assertFalse(self.commit(row, store)["started"])
        pending = self.new(key="interrupted")
        begun = self.store._begin(self.task, pending["id"], pending["revision"], pending["digest"])
        self.authority.close()
        reopened_authority = Authority(self.db_path)
        self.addCleanup(reopened_authority.close)
        reopened = Actions(reopened_authority, self.targets)
        self.assertEqual("executing", reopened.get(self.task, pending["id"])["action"]["status"])
        self.assertEqual(1, reopened.recover())
        self.assertEqual(0, reopened.recover())
        result = self.commit(pending, reopened)
        self.assertFalse(result["started"])
        self.assertEqual("unconfirmed", result["action"]["status"])
        self.assertEqual(begun["action"]["attempt_id"], result["action"]["attempt_id"])
        self.assertEqual([], self.receiver.received)

    def test_agent_cannot_supply_urls_paths_headers_or_arbitrary_form_fields(self):
        invalid = [
            {"kind": "exec", "target_id": "chat", "payload": {"command": "anything"}},
            {"kind": "message", "target_id": "https://example.test", "payload": {"body": "x"}},
            {"kind": "message", "target_id": "chat", "payload": {"body": "x", "url": "https://example.test"}},
            {"kind": "message", "target_id": "chat", "payload": {"body": "x"}, "headers": {}},
            {"kind": "upload", "target_id": "files", "payload": {"path": "/etc/passwd"}},
            {"kind": "upload", "target_id": "files", "payload": {"filename": "../../bad", "content": "x"}},
            {"kind": "form", "target_id": "request", "payload": {"fields": {"name": "x", "note": "y", "admin": "true"}}},
        ]
        for proposal in invalid:
            with self.subTest(proposal=proposal), self.assertRaises(ValueError):
                validate_proposal(proposal, self.targets)
        for url in ("http://example.test", "http://localhost", "https://user:password@example.test/", "https://example.test/#fragment", "file:///tmp/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ActionTarget("message", "invalid", url=url)
        for headers in ({"Host": "evil"}, {"Authorization": "x\r\nInjected: yes"}, {"Content-Length": "0"}):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                ActionTarget("message", "invalid", port=self.receiver.port, headers=headers)
        ActionTarget("message", "固定 HTTPS 服务，只检查配置不发送", url="https://example.test/api/messages")
        self.assertEqual([], self.receiver.received)

    def test_host_only_file_review_overwrites_and_deletes_exact_selected_files(self):
        root = self.files()
        overwrite = self.new("overwrite", "report", {"content": "新的完整报告\n"})
        delete = self.new("delete", "discard", {}, key="delete")
        self.assertNotIn("before", overwrite)
        viewed = self.store.get(self.task, overwrite["id"])["action"]
        self.assertEqual("旧文件：私密内容\n", viewed["before"]["content"])
        self.assertEqual(str(root / "report.txt"), viewed["target"]["destination"])
        self.assertEqual("acknowledged", self.commit(overwrite)["action"]["status"])
        self.assertEqual("新的完整报告\n", (root / "report.txt").read_text(encoding="utf-8"))
        self.assertEqual("acknowledged", self.commit(delete)["action"]["status"])
        self.assertFalse((root / "discard.txt").exists())
        self.assertFalse(self.commit(overwrite)["started"])
        self.assertFalse(self.commit(delete)["started"])
        self.assertEqual([], list(root.glob(".yuanxingmu-*")))

    def test_modified_file_or_replaced_directory_requires_new_review(self):
        root = self.files()
        row = self.new("overwrite", "report", {"content": "approved"})
        (root / "report.txt").write_text("unreviewed host edit")
        self.denied("action_file_changed", self.commit, row)
        self.assertEqual("unreviewed host edit", (root / "report.txt").read_text())
        proposal = {"kind": "overwrite", "target_id": "report", "payload": {"content": "new approval"}}
        refreshed = self.store.edit(self.task, row["id"], row["revision"], row["digest"], proposal)
        self.assertEqual("unreviewed host edit", refreshed["before"]["content"])
        root.rename(root.with_name("old-host-files"))
        root.mkdir(mode=0o700)
        (root / "report.txt").write_text("replacement directory")
        self.denied("action_file_unavailable", self.commit, refreshed)
        self.assertEqual("replacement directory", (root / "report.txt").read_text())

    def test_workspace_alias_is_canonical_for_broker_overlap_checks(self):
        root = self.files()
        aliased = ActionTarget("overwrite", "host selected file", workspace=root / ".." / root.name, relative_path="report.txt")
        self.assertEqual(root, aliased.workspace)
        self.assertEqual(str(root), aliased.binding()["workspace"])

    def test_revocation_orders_after_an_inflight_commit_and_blocks_later_one(self):
        first = self.new(key="first")
        second = self.new(key="second")
        entered, release, revoke_started = threading.Event(), threading.Event(), threading.Event()
        self.receiver.callback = lambda: (entered.set(), release.wait(2))
        def revoke():
            revoke_started.set()
            self.authority.revoke(self.task)
        with ThreadPoolExecutor(max_workers=2) as pool:
            sending = pool.submit(self.commit, first)
            self.assertTrue(entered.wait(2))
            revoking = pool.submit(revoke)
            self.assertTrue(revoke_started.wait(2))
            self.assertFalse(revoking.done())
            release.set()
            self.assertEqual("acknowledged", sending.result(timeout=3)["action"]["status"])
            revoking.result(timeout=3)
        self.denied("task_revoked", self.commit, second)
        self.assertEqual(1, len(self.receiver.received))

    def test_symlinks_hardlinks_special_files_and_traversal_never_change_outside_file(self):
        root = self.files()
        outside = self.directory / "outside.txt"
        outside.write_text("OUTSIDE MUST REMAIN UNCHANGED")
        (root / "report.txt").unlink()
        (root / "report.txt").symlink_to(outside)
        self.denied("action_file_unavailable", self.new, "overwrite", "report", {"content": "replacement"})
        (root / "report.txt").unlink()
        os.link(outside, root / "report.txt")
        self.denied("action_file_unavailable", self.new, "overwrite", "report", {"content": "replacement"})
        (root / "report.txt").unlink()
        os.mkfifo(root / "report.txt", 0o600)
        self.denied("action_file_unavailable", self.new, "overwrite", "report", {"content": "replacement"})
        ancestor = root / "linked"
        ancestor.symlink_to(self.directory, target_is_directory=True)
        target = ActionTarget("delete", "must reject ancestor", workspace=root, relative_path="linked/outside.txt")
        unsafe = Actions(self.authority, {"unsafe": target})
        self.denied("action_file_unavailable", self.new, "delete", "unsafe", {}, store=unsafe)
        for path in ("../outside.txt", "/etc/passwd", "a/../../b", "a\\b", "C:secret"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                ActionTarget("delete", "invalid", workspace=root, relative_path=path)
        symlink_root = self.directory / "linked-root"
        symlink_root.symlink_to(root, target_is_directory=True)
        with self.assertRaises(ValueError):
            ActionTarget("delete", "invalid", workspace=symlink_root, relative_path="report.txt")
        self.assertEqual("OUTSIDE MUST REMAIN UNCHANGED", outside.read_text())

    def test_host_change_during_replacement_preparation_preserves_new_file_and_consumes_attempt(self):
        root = self.files()
        row = self.new("overwrite", "report", {"content": "approved"})
        original_fsync, changed = os.fsync, []
        def change_after_write(fd):
            original_fsync(fd)
            if not changed:
                changed.append(True)
                (root / "report.txt").write_text("concurrent host edit")
        with patch("yuanxingmu.actions.os.fsync", side_effect=change_after_write):
            result = self.commit(row)
        self.assertEqual("not_started", result["action"]["status"])
        self.assertEqual("concurrent host edit", (root / "report.txt").read_text())
        self.assertFalse(self.commit(row)["started"])
        self.assertEqual([], list(root.glob(".yuanxingmu-*")))

    def test_payload_and_existing_file_size_limits_and_cancel_are_enforced(self):
        self.denied("invalid_action_body", self.new, payload={"body": "x" * (MAX_CONTENT_BYTES + 1)})
        row = self.new()
        cancelled = self.store.cancel(self.task, row["id"], row["revision"], row["digest"])
        self.assertEqual("cancelled", cancelled["status"])
        self.denied("action_not_pending", self.commit, row)
        root = self.files()
        (root / "report.txt").write_bytes(b"x" * (MAX_CONTENT_BYTES + 1))
        self.denied("action_file_unavailable", self.new, "overwrite", "report", {"content": "small"}, key="large")
        (root / "report.txt").write_bytes(b"\xff\xfe")
        self.denied("action_file_unavailable", self.new, "overwrite", "report", {"content": "small"}, key="binary")


if __name__ == "__main__":
    unittest.main()
