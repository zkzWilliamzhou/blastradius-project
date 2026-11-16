import json
import os
import tempfile
import unittest
from pathlib import Path

from blastradius.policy import Policy, PolicyError, evaluate, write_preset, PRESETS
from blastradius.rules import analyze, PROTECTED_DEFAULT
from blastradius.score import assess


def run(cmd, policy):
    findings = analyze(cmd, protected=policy.protected)
    a = assess(findings, ask_at=policy.score_ask, deny_at=policy.score_deny)
    return findings, a, evaluate(cmd, findings, a.score, policy)


class TestPresets(unittest.TestCase):
    def test_every_preset_loads(self):
        for name, data in PRESETS.items():
            p = Policy.from_dict(data)
            self.assertEqual(p.name, name if name != "default" else "balanced")

    def test_strict_denies_secret_read(self):
        p = Policy.from_dict(PRESETS["strict"])
        _, _, d = run("cat ~/.ssh/id_rsa", p)
        self.assertEqual(d.action, "deny")

    def test_permissive_allows_secret_read(self):
        p = Policy.from_dict(PRESETS["permissive"])
        _, _, d = run("cat ~/.ssh/id_rsa", p)
        self.assertIn(d.action, ("allow", "ask"))
        self.assertNotEqual(d.action, "deny")

    def test_strict_asks_everything(self):
        p = Policy.from_dict(PRESETS["strict"])
        _, _, d = run("ls -la", p)
        self.assertEqual(d.action, "ask")


class TestPrecedence(unittest.TestCase):
    def test_deny_beats_allow(self):
        p = Policy.from_dict({
            "default": "auto",
            "rules": [
                {"action": "allow", "capability": "fs.delete"},
                {"action": "deny", "rule": "BR001"},
            ],
        })
        _, _, d = run("rm -rf /", p)
        self.assertEqual(d.action, "deny")

    def test_allow_rule_can_downgrade_score(self):
        p = Policy.from_dict({
            "default": "auto",
            "rules": [{"action": "allow", "program": "rm", "path_glob": "/tmp/**",
                       "reason": "scratch space"}],
        })
        _, a, d = run("rm -rf /tmp/build", p)
        self.assertEqual(d.action, "allow")

    def test_policy_default_overrides_auto(self):
        p = Policy.from_dict({"default": "ask", "rules": []})
        _, _, d = run("ls", p)
        self.assertEqual(d.action, "ask")

    def test_rule_without_conditions_is_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"default": "auto", "rules": [{"action": "deny"}]})


class TestGlobMatching(unittest.TestCase):
    def test_dotenv_pattern(self):
        from blastradius.rules import protected_by
        for path in (".env", "config/.env", "/app/.env", "a/b/.env.production"):
            self.assertIsNotNone(protected_by(path, ["**/.env", "**/.env.*"]), path)

    def test_dotenv_example_excluded(self):
        from blastradius.rules import protected_by
        for path in (".env.example", "x/.env.sample", ".env.template"):
            self.assertIsNone(protected_by(path, ["**/.env.*"]), path)

    def test_home_expansion(self):
        from blastradius.rules import protected_by
        self.assertIsNotNone(protected_by("~/.aws/credentials", PROTECTED_DEFAULT))
        self.assertIsNotNone(protected_by("$HOME/.aws/credentials", PROTECTED_DEFAULT))
        self.assertIsNotNone(protected_by("/home/u/.ssh/id_rsa", PROTECTED_DEFAULT))

    def test_path_glob_policy(self):
        p = Policy.from_dict({
            "default": "auto",
            "rules": [{"action": "deny", "path_glob": "/srv/prod/**"}],
        })
        _, _, d = run("rm -rf /srv/prod/data", p)
        self.assertEqual(d.action, "deny")
        _, _, d = run("rm -rf /srv/staging/data", p)
        self.assertEqual(d.action, "allow")


class TestValidation(unittest.TestCase):
    def test_bad_action(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"action": "nuke"}]})

    def test_bad_thresholds(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"score_ask": 80, "score_deny": 20})

    def test_bad_version(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"version": 99})

    def test_bad_severity(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"action": "deny", "severity_min": "apocalyptic"}]})

    def test_unknown_key_is_rejected_with_suggestion(self):
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_dict({"rules": [{"action": "deny", "capabilty": "fs.delete"}]})
        self.assertIn("capability", str(ctx.exception))

    def test_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            name = fh.name
        try:
            with self.assertRaises(PolicyError):
                Policy.load(name)
        finally:
            os.unlink(name)

    def test_missing_file(self):
        with self.assertRaises(PolicyError):
            Policy.load("/nonexistent/policy.json")

    def test_write_preset_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_preset("strict", Path(d) / "p.json")
            p = Policy.load(path)
            self.assertEqual(p.name, "strict")
            self.assertEqual(json.loads(path.read_text())["version"], 1)


if __name__ == "__main__":
    unittest.main()
