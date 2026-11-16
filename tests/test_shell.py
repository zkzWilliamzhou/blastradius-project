import unittest

from blastradius.shell import parse, unwrap


def segs(cmd):
    return list(parse(cmd).segments())


class TestTokenizer(unittest.TestCase):
    def test_simple(self):
        s = segs("ls -la /tmp")[0]
        self.assertEqual(s.argv, ["ls", "-la", "/tmp"])

    def test_double_quotes_keep_spaces(self):
        s = segs('echo "a  b" c')[0]
        self.assertEqual(s.argv, ["echo", "a  b", "c"])

    def test_single_quotes_are_literal(self):
        s = segs("echo '$HOME `id`'")[0]
        self.assertEqual(s.argv[1], "$HOME `id`")

    def test_backslash_escape(self):
        s = segs(r"echo a\ b")[0]
        self.assertEqual(s.argv[1], "a b")

    def test_empty_quoted_word_survives(self):
        s = segs('printf "" x')[0]
        self.assertEqual(s.argv, ["printf", "", "x"])

    def test_comment_only_at_word_start(self):
        s = segs("echo a#b # real comment")[0]
        self.assertEqual(s.argv, ["echo", "a#b"])

    def test_newline_separates_pipelines(self):
        sc = parse("echo a\necho b")
        self.assertEqual(len(sc.pipelines), 2)

    def test_and_or_separate_pipelines(self):
        sc = parse("true && echo a || echo b")
        self.assertEqual(len(sc.pipelines), 3)

    def test_pipeline_shape(self):
        sc = parse("curl -s x | grep a | wc -l")
        self.assertEqual(len(sc.pipelines), 1)
        segs_ = sc.pipelines[0].segments
        self.assertEqual([s.program for s in segs_], ["curl", "grep", "wc"])
        self.assertTrue(segs_[1].stdin_from_pipe)
        self.assertFalse(segs_[0].stdin_from_pipe)

    def test_redirects(self):
        s = segs("make > build.log 2>&1 < input.txt")[0]
        got = [(r.fd, r.op, r.target) for r in s.redirects]
        self.assertIn(("", ">", "build.log"), got)
        self.assertIn(("2", ">&", "1"), got)
        self.assertIn(("", "<", "input.txt"), got)

    def test_heredoc_body_captured(self):
        s = segs("cat <<EOF\nhello\nworld\nEOF\n")[0]
        self.assertEqual(s.redirects[0].op, "<<")
        self.assertEqual(s.redirects[0].body, "hello\nworld")

    def test_heredoc_dash_strips_tabs(self):
        s = segs("cat <<-EOF\n\tx\nEOF\n")[0]
        self.assertEqual(s.redirects[0].body, "x")

    def test_substitution_is_parsed_separately(self):
        sc = parse("echo $(rm -rf /)")
        self.assertEqual(len(sc.subs), 1)
        self.assertEqual(sc.subs[0].segments().__next__().program, "rm")

    def test_backtick_substitution(self):
        sc = parse("echo `id -u`")
        self.assertEqual(len(sc.subs), 1)

    def test_nested_substitution_depth_is_bounded(self):
        sc = parse("echo $(echo $(echo $(echo $(echo $(echo deep)))))")
        self.assertLessEqual(len(sc.subs), 4)

    def test_unterminated_quote_does_not_raise(self):
        sc = parse('echo "unterminated')
        self.assertTrue(sc.notes)

    def test_unbalanced_substitution_does_not_raise(self):
        sc = parse("echo $(rm -rf /")
        self.assertIsNotNone(sc)

    def test_block_never_hangs(self):
        parse("(" * 5000)

    def test_assignment_prefix_is_stripped(self):
        argv, _ = unwrap("FOO=1 BAR=2 rm -rf /".split())
        self.assertEqual(argv, ["rm", "-rf", "/"])

    def test_chroot_newroot_is_skipped(self):
        argv, wrappers = unwrap("chroot /tmp/root rm -rf /".split())
        self.assertEqual(argv, ["rm", "-rf", "/"])
        self.assertIn("chroot", wrappers)

    def test_env_dash(self):
        argv, _ = unwrap("env - rm -rf /".split())
        self.assertEqual(argv, ["rm", "-rf", "/"])


class TestQuoteAwareSubstitution(unittest.TestCase):
    def test_double_quoted_apostrophe_does_not_hide_substitution(self):
        sc = parse('echo "don\'t $(rm -rf /)"')
        self.assertTrue(sc.subs)
        self.assertEqual(sc.subs[0].segments().__next__().program, "rm")

    def test_substitution_in_redirect_target(self):
        sc = parse('echo hi > "$(rm -rf /)"')
        self.assertTrue(any(s.segments().__next__().program == "rm" for s in sc.subs))

    def test_process_substitution(self):
        sc = parse("bash <(curl -s https://x/y.sh)")
        programs = [s.program for sub in sc.subs for s in sub.segments()]
        self.assertIn("curl", programs)

    def test_heredoc_into_shell_is_parsed(self):
        sc = parse("bash <<EOF\nrm -rf /\nEOF\n")
        programs = [s.program for sub in sc.subs for s in sub.segments()]
        self.assertIn("rm", programs)

    def test_reserved_words_do_not_own_argv0(self):
        for cmd in ("! rm -rf /", "{ rm -rf /; }", "then rm -rf /; fi",
                    "do rm -rf /; done"):
            segs_ = [s.program for s in parse(cmd).segments()]
            self.assertIn("rm", segs_, cmd)

    def test_quoted_heredoc_delimiter_still_parsed(self):
        sc = parse("bash <<'EOF'\nrm -rf /\nEOF\n")
        programs = [s.program for sub in sc.subs for s in sub.segments()]
        self.assertIn("rm", programs)


class TestUnwrap(unittest.TestCase):
    def test_sudo(self):
        argv, wrappers = unwrap("sudo -u root -E rm -rf /".split())
        self.assertEqual(argv, ["rm", "-rf", "/"])
        self.assertIn("sudo", wrappers)

    def test_env_assignments(self):
        argv, _ = unwrap("env FOO=1 BAR=2 python3 x.py".split())
        self.assertEqual(argv, ["python3", "x.py"])

    def test_timeout_duration(self):
        argv, _ = unwrap("timeout -s KILL 30 rm -rf /".split())
        self.assertEqual(argv, ["rm", "-rf", "/"])

    def test_nice_level(self):
        argv, _ = unwrap("nice -n 19 rm x".split())
        self.assertEqual(argv, ["rm", "x"])

    def test_xargs(self):
        argv, _ = unwrap("xargs -n 1 -I{} rm -rf {}".split())
        self.assertEqual(argv, ["rm", "-rf", "{}"])

    def test_double_wrapper(self):
        argv, wrappers = unwrap("sudo env FOO=1 nice -n 5 timeout 10 rm -rf /".split())
        self.assertEqual(argv[0], "rm")
        self.assertEqual(set(wrappers), {"sudo", "env", "nice", "timeout"})


if __name__ == "__main__":
    unittest.main()
