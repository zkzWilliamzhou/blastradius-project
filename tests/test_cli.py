import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from blastradius.cli import main


def run(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    old = os.sys.stdin
    os.sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
    finally:
        os.sys.stdin = old
    return code, out.getvalue(), err.getvalue()


class TestExitCodes(unittest.TestCase):
    def test_allow(self):
        code, out, _ = run("check", "ls -la")
        self.assertEqual(code, 0)
        self.assertIn("ALLOW", out)

    def test_ask(self):
        code, out, _ = run("check", "cat ~/.ssh/id_rsa")
        self.assertEqual(code, 2)
        self.assertIn("ASK", out)

    def test_deny(self):
        code, out, _ = run("check", "rm -rf /")
        self.assertEqual(code, 3)
        self.assertIn("DENY", out)

    def test_empty(self):
        code, _, err = run("check", stdin="   ")
        self.assertEqual(code, 4)
        self.assertIn("empty", err)

    def test_unknown_policy(self):
        code, _, err = run("check", "--policy", "/nope.json", "ls")
        self.assertEqual(code, 4)

    def test_shorthand_invocation(self):
        code, out, _ = run("rm -rf /")
        self.assertEqual(code, 3)


class TestJson(unittest.TestCase):
    def test_check_json_shape(self):
        code, out, _ = run("check", "--json", "rm -rf /")
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "deny")
        self.assertEqual(payload["tool"], "blastradius")
        self.assertGreater(payload["score"], 60)
        self.assertTrue(payload["findings"])
        f = payload["findings"][0]
        for key in ("rule", "title", "capability", "severity", "detail", "evidence", "mitigation"):
            self.assertIn(key, f)

    def test_rules_json(self):
        code, out, _ = run("rules", "--json")
        rules = json.loads(out)
        self.assertGreaterEqual(len(rules), 40)
        ids = {r["id"] for r in rules}
        self.assertIn("BR001", ids)
        self.assertIn("BR030", ids)

    def test_explain(self):
        code, out, _ = run("explain", "sudo rm -rf /tmp/x | tee log")
        self.assertEqual(code, 0)
        self.assertIn("wrappers", out)
        self.assertIn("pipeline", out)


class TestHook(unittest.TestCase):
    def hook(self, payload):
        return run("guard", stdin=json.dumps(payload))

    def test_deny_payload(self):
        code, out, _ = self.hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("permissionDecisionReason", data["hookSpecificOutput"])
        self.assertIn("blastradius", data["systemMessage"])

    def test_allow_payload(self):
        code, out, _ = self.hook({"tool_input": {"command": "npm test"}})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_non_bash_tool_passes(self):
        code, out, _ = self.hook({"tool_name": "Read", "tool_input": {"path": "a.txt"}})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_garbage_json_still_answers(self):
        code, out, _ = run("guard", stdin="{oops")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_json_envelope_embeds_report(self):
        code, out, _ = run("guard", "--json", stdin=json.dumps({"tool_input": {"command": "dd if=/dev/zero of=/dev/sda"}}))
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertTrue(data.get("blastradius", {}).get("findings"))


class TestFiles(unittest.TestCase):
    def test_command_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write("rm -rf /\n")
            name = fh.name
        try:
            code, _, _ = run("check", "-f", name)
            self.assertEqual(code, 3)
        finally:
            os.unlink(name)

    def test_policy_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps({
                "version": 1, "default": "auto",
                "rules": [{"action": "deny", "capability": "fs.delete"}],
            }))
            code, _, _ = run("check", "--policy", str(path), "rm -rf node_modules")
            self.assertEqual(code, 3)

    def test_policy_init(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "br-policy.json"
            code, out, _ = run("policy", "init", "--preset", "strict", "-o", str(target))
            self.assertEqual(code, 0)
            self.assertTrue(target.exists())
            data = json.loads(target.read_text())
            self.assertEqual(data["name"], "strict")

    def test_stdin_command(self):
        code, out, _ = run("check", "-", stdin="rm -rf /\n")
        self.assertEqual(code, 3)


class TestContract(unittest.TestCase):
    def test_usage_error_is_4_not_2(self):
        code, _, err = run("--nope")
        self.assertEqual(code, 4)
        self.assertIn("error", err)

    def test_unknown_subcommand_suggests(self):
        code, _, err = run("chek", "ls")
        self.assertEqual(code, 4)
        self.assertIn("did you mean", err)

    def test_json_flag_shorthand(self):
        code, out, _ = run("--json", "rm -rf /")
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["decision"], "deny")

    def test_policy_without_subcommand_is_usage_error(self):
        code, _, _ = run("policy")
        self.assertEqual(code, 4)

    def test_help_documents_exit_codes(self):
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("exit codes", out)

    def test_guard_bad_json_still_answers(self):
        code, out, _ = run("guard", stdin="{not json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_guard_bad_policy_still_answers(self):
        code, out, _ = run("guard", "--policy", "/nope.json",
                           stdin=json.dumps({"tool_input": {"command": "ls"}}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_policy_typo_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps({"rules": [{"action": "deny", "capabilty": "fs.delete"}]}))
            code, _, err = run("check", "--policy", str(path), "ls")
            self.assertEqual(code, 4)
            self.assertIn("capabilty", err)

    def test_policy_bad_severity_is_rejected_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps({"rules": [{"action": "deny", "severity_min": "servere"}]}))
            code, _, err = run("check", "--policy", str(path), "ls")
            self.assertEqual(code, 4)
            self.assertIn("servere", err)

    def test_policy_rule_without_condition_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps({"rules": [{"action": "deny"}]}))
            code, _, err = run("check", "--policy", str(path), "ls")
            self.assertEqual(code, 4)


class TestSelftest(unittest.TestCase):
    def test_corpus_green(self):
        code, out, _ = run("selftest")
        self.assertEqual(code, 0, out)
        self.assertIn("cases pass", out)


if __name__ == "__main__":
    unittest.main()
