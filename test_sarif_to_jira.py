"""Unit tests for sarif-to-jira.py (NV-4419, NV-4414).

Runs on the standard library only (no jira package, no pytest):

    python3 -m unittest test_sarif_to_jira -v

A FakeJira stands in for the real client so dedup, severity mapping, dry-run,
and 429 backoff are exercised without a live Jira. Pure helpers (max-issues
validation, correlation keys, Markdown-to-ADF rendering) are tested directly.
"""

import argparse
import importlib.util
import os
import re
import unittest

# The module file name contains a dash, so load it by path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("sarif_to_jira", os.path.join(_HERE, "sarif-to-jira.py"))
s2j = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s2j)


def make_result(kind, endpoint=None, uri="/", start_line=None, risk=None, fingerprint=None, rule_id=None):
    region = {}
    if endpoint is not None:
        region["message"] = {"text": "Found on endpoint " + endpoint}
    if start_line is not None:
        region["startLine"] = start_line
    properties = {}
    if risk is not None:
        properties["nightvision-risk"] = risk
    if fingerprint is not None:
        properties["nightvision-fingerprint"] = fingerprint
    return {
        "ruleId": rule_id or (kind + "-id"),
        "message": {"text": kind},
        "properties": properties,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": region,
            }
        }],
    }


def make_sarif(results, rules=None):
    return {"runs": [{
        "tool": {"driver": {"rules": rules or []}},
        "results": results,
    }]}


class FakeIssue:
    def __init__(self, key):
        self.key = key


class FakeJira:
    """Records created issues and indexes their labels so search-before-create works."""

    def __init__(self):
        self.created = []
        self._labels = set()

    def search_issues(self, jql, maxResults=1):
        m = re.search(r'labels = "([^"]+)"', jql)
        label = m.group(1) if m else None
        return [FakeIssue("EXIST-1")] if label in self._labels else []

    def create_issue(self, fields):
        key = "NV-%d" % (len(self.created) + 1)
        self.created.append(fields)
        for label in fields.get("labels", []):
            self._labels.add(label)
        return FakeIssue(key)


class FlakyJira(FakeJira):
    """Raises 429 a fixed number of times on create before succeeding."""

    def __init__(self, fail_times):
        super().__init__()
        self.remaining_failures = fail_times

    def create_issue(self, fields):
        if self.remaining_failures > 0:
            self.remaining_failures -= 1
            raise s2j.JIRAError(text="rate limited", status_code=429)
        return super().create_issue(fields)


class FlakySearchJira(FakeJira):
    """Raises 429 a fixed number of times on search before succeeding."""

    def __init__(self, fail_times):
        super().__init__()
        self.remaining_failures = fail_times

    def search_issues(self, jql, maxResults=1):
        if self.remaining_failures > 0:
            self.remaining_failures -= 1
            raise s2j.JIRAError(text="rate limited", status_code=429)
        return super().search_issues(jql, maxResults=maxResults)


class JQLRecordingJira(FakeJira):
    """Records every JQL string passed to search, for injection-safety assertions."""

    def __init__(self):
        super().__init__()
        self.queries = []

    def search_issues(self, jql, maxResults=1):
        self.queries.append(jql)
        return super().search_issues(jql, maxResults=maxResults)


class OneCreateFailsJira(FakeJira):
    """Raises a non-429 error on the one create whose summary matches a marker."""

    def __init__(self, fail_summary_substr):
        super().__init__()
        self.fail_summary_substr = fail_summary_substr

    def create_issue(self, fields):
        if self.fail_summary_substr in fields["summary"]:
            raise s2j.JIRAError(text="bad request", status_code=400)
        return super().create_issue(fields)


def silent(*_args, **_kwargs):
    pass


class CorrelationKeyTests(unittest.TestCase):
    def test_prefers_durable_fingerprint(self):
        r = make_result("SQL Injection", endpoint="/api/orders", fingerprint="deadbeef")
        key, scheme = s2j.correlation_key(r)
        self.assertEqual(key, "deadbeef")
        self.assertEqual(scheme, "fingerprint")

    def test_best_effort_when_no_fingerprint(self):
        r = make_result("SQL Injection", endpoint="/api/orders", uri="Foo.java", start_line=42)
        key, scheme = s2j.correlation_key(r)
        self.assertEqual(scheme, "best-effort")
        self.assertEqual(len(key), 64)  # sha256 hex

    def test_best_effort_is_stable_and_sensitive(self):
        a = make_result("SQLi", endpoint="/api/orders", uri="Foo.java", start_line=42)
        b = make_result("SQLi", endpoint="/api/orders", uri="Foo.java", start_line=42)
        c = make_result("SQLi", endpoint="/api/users", uri="Foo.java", start_line=42)
        self.assertEqual(s2j.best_effort_key(a), s2j.best_effort_key(b))
        self.assertNotEqual(s2j.best_effort_key(a), s2j.best_effort_key(c))

    def test_whitespace_only_fingerprint_is_absent(self):
        r = make_result("SQLi", endpoint="/api/orders", uri="Foo.java", start_line=42, fingerprint="   ")
        key, scheme = s2j.correlation_key(r)
        self.assertEqual(scheme, "best-effort")
        self.assertEqual(key, s2j.best_effort_key(r))

    def test_unsafe_fingerprint_is_normalized_to_safe_key(self):
        # A producer fingerprint with a space / quote would break the Jira label and
        # the JQL search; it must be hashed into a safe charset.
        r = make_result("SQLi", endpoint="/a", fingerprint='bad "key" with spaces')
        key, scheme = s2j.correlation_key(r)
        self.assertEqual(scheme, "fingerprint")
        self.assertRegex(key, r"^[a-f0-9]{64}$")
        # Stable for the same input.
        self.assertEqual(key, s2j.correlation_key(r)[0])

    def test_overlong_fingerprint_is_hashed(self):
        r = make_result("SQLi", endpoint="/a", fingerprint="a" * 200)
        key, _ = s2j.correlation_key(r)
        self.assertRegex(key, r"^[a-f0-9]{64}$")

    def test_clean_hex_fingerprint_passes_through(self):
        fp = "a" * 64
        r = make_result("SQLi", endpoint="/a", fingerprint=fp)
        key, scheme = s2j.correlation_key(r)
        self.assertEqual((key, scheme), (fp, "fingerprint"))


class PriorityAndSummaryTests(unittest.TestCase):
    def test_priority_map(self):
        self.assertEqual(s2j.map_priority("CRITICAL"), "Highest")
        self.assertEqual(s2j.map_priority("critical"), "Highest")
        self.assertEqual(s2j.map_priority("INFO"), "Lowest")
        self.assertIsNone(s2j.map_priority("BOGUS"))
        self.assertIsNone(s2j.map_priority(None))

    def test_summary_includes_endpoint(self):
        # No rule in the run: falls back to message.text for the class name.
        r = make_result("SQL Injection", endpoint="/api/orders")
        self.assertEqual(s2j.build_summary(r, {}), "SQL Injection at /api/orders")

    def test_summary_without_endpoint(self):
        r = make_result("Missing Security Headers")
        self.assertEqual(s2j.build_summary(r, {}), "Missing Security Headers")

    def test_summary_prefers_rule_name_over_message(self):
        # The summary class name comes from the rule, not message.text.
        r = make_result("ignored message text", endpoint="/api/orders", rule_id="xss-id")
        run = {"tool": {"driver": {"rules": [
            {"id": "xss-id", "name": "Cross Site Scripting (DOM Based)"}]}}}
        self.assertEqual(
            s2j.build_summary(r, run),
            "Cross Site Scripting (DOM Based) at /api/orders")

    def test_summary_falls_back_to_rule_short_description(self):
        r = make_result("ignored", rule_id="r1")
        run = {"tool": {"driver": {"rules": [
            {"id": "r1", "shortDescription": {"text": "SQL Injection"}}]}}}
        self.assertEqual(s2j.build_summary(r, run), "SQL Injection")

    def test_summary_from_cli_banner_is_single_line_and_bounded(self):
        # Regression for the CLI producer: message.text is a long multi-line banner,
        # the short class name is in rule.name. The summary must be single-line,
        # <= 255 chars, and carry the rule name, not the banner.
        banner = (
            "Exploitable Vulnerability Found\n\n"
            "Cross Site Scripting (DOM Based) on endpoint /search\n\n"
            "For more information see the issue on NightVision here: "
            "https://app.nightvision.net/scans/abc/issues/def\n" + ("x" * 3000))
        r = make_result(banner, endpoint="/search", rule_id="xss-id")
        run = {"tool": {"driver": {"rules": [
            {"id": "xss-id", "name": "Cross Site Scripting (DOM Based)"}]}}}
        summary = s2j.build_summary(r, run)
        self.assertEqual(summary, "Cross Site Scripting (DOM Based) at /search")
        self.assertLessEqual(len(summary), s2j.JIRA_SUMMARY_MAX)
        self.assertNotIn("\n", summary)
        s2j.validate_summary(summary)  # must not raise

    def test_normalize_summary_truncates_and_strips_newlines(self):
        long_kind = "A" * 300
        out = s2j.normalize_summary(long_kind + "\nmore")
        self.assertEqual(len(out), s2j.JIRA_SUMMARY_MAX)
        self.assertTrue(out.endswith("..."))
        self.assertNotIn("\n", out)
        s2j.validate_summary(out)  # must not raise

    def test_validate_summary_rejects_overlong_and_multiline(self):
        with self.assertRaises(ValueError):
            s2j.validate_summary("x" * (s2j.JIRA_SUMMARY_MAX + 1))
        with self.assertRaises(ValueError):
            s2j.validate_summary("line one\nline two")


class ImportLoopTests(unittest.TestCase):
    def setUp(self):
        self.priorities = {"Highest", "High", "Medium", "Low", "Lowest"}
        self.sarif = make_sarif([
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="fp-critical"),
            make_result("Verbose Banner", endpoint="/api/info", risk="LOW", fingerprint="fp-low"),
        ])

    def _run(self, jira, **kw):
        defaults = dict(
            project_id="10001", issue_type="Task", component_id=None,
            valid_priorities=self.priorities, sleep_fn=silent, log=silent,
        )
        defaults.update(kw)
        return s2j.import_findings(jira, self.sarif, **defaults)

    def test_creates_with_mapped_priorities(self):
        jira = FakeJira()
        counts = self._run(jira)
        self.assertEqual(counts["created"], 2)
        names = sorted(f["priority"]["name"] for f in jira.created)
        self.assertEqual(names, ["Highest", "Low"])  # CRITICAL->Highest, LOW->Low
        # Every ticket carries the nightvision label plus its fp label.
        for f in jira.created:
            self.assertIn("nightvision", f["labels"])
            self.assertTrue(any(l.startswith(s2j.FP_LABEL_PREFIX) for l in f["labels"]))

    def test_second_run_dedups(self):
        jira = FakeJira()
        self._run(jira)
        counts = self._run(jira)  # same fake retains the labels from run 1
        self.assertEqual(counts["created"], 0)
        self.assertEqual(counts["skipped"], 2)
        self.assertEqual(len(jira.created), 2)  # unchanged

    def test_in_report_duplicate_dedups(self):
        dup = make_sarif([
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="fp-x"),
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="fp-x"),
        ])
        jira = FakeJira()
        counts = s2j.import_findings(
            jira, dup, project_id="1", issue_type="Task", component_id=None,
            valid_priorities=self.priorities, sleep_fn=silent, log=silent)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(counts["skipped"], 1)

    def test_dry_run_creates_nothing(self):
        jira = FakeJira()
        counts = self._run(jira, dry_run=True)
        self.assertEqual(counts["created"], 0)
        self.assertEqual(counts["planned"], 2)
        self.assertEqual(jira.created, [])

    def test_max_issues_cap(self):
        jira = FakeJira()
        counts = self._run(jira, max_issues=1)
        self.assertEqual(counts["created"], 1)

    def test_priority_omitted_when_scheme_lacks_it(self):
        jira = FakeJira()
        self._run(jira, valid_priorities={"Blocker", "Trivial"})
        for f in jira.created:
            self.assertNotIn("priority", f)

    def test_429_is_retried(self):
        sarif = make_sarif([make_result("SQLi", endpoint="/a", risk="HIGH", fingerprint="fp1")])
        jira = FlakyJira(fail_times=2)
        slept = []
        counts = s2j.import_findings(
            jira, sarif, project_id="1", issue_type="Task", component_id=None,
            valid_priorities=self.priorities, sleep_fn=slept.append, log=silent)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(slept), 2)  # two backoffs before success

    def test_429_on_search_is_retried(self):
        # _retry_on_429 wraps the find_existing search too, not just create.
        sarif = make_sarif([make_result("SQLi", endpoint="/a", risk="HIGH", fingerprint="fp1")])
        jira = FlakySearchJira(fail_times=2)
        slept = []
        counts = s2j.import_findings(
            jira, sarif, project_id="1", issue_type="Task", component_id=None,
            valid_priorities=self.priorities, sleep_fn=slept.append, log=silent)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(slept), 2)  # two search backoffs before the search succeeds


class MaxIssuesValidationTests(unittest.TestCase):
    def test_positive_int_accepts_one_or_greater(self):
        self.assertEqual(s2j.positive_int("1"), 1)
        self.assertEqual(s2j.positive_int("3"), 3)

    def test_positive_int_rejects_zero_and_negative(self):
        # A non-positive cap would make --max-issues a silent no-op (exit 0); it
        # must fail fast at parse time.
        for bad in ("0", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                s2j.positive_int(bad)


class SarifShapeValidationTests(unittest.TestCase):
    def test_accepts_documents_with_a_runs_list(self):
        s2j.require_runs({"runs": []})  # empty but structurally valid SARIF
        s2j.require_runs(make_sarif([]))
        s2j.require_runs(make_sarif([make_result("SQLi", endpoint="/a")]))

    def test_rejects_valid_json_that_is_not_sarif(self):
        # The fail-open J guards against: valid JSON lacking a top-level runs array
        # must raise (-> non-zero exit) instead of silently importing nothing.
        for bad in ({}, None, [], 5, {"runs": "x"}, {"runs": None}):
            with self.assertRaises(ValueError):
                s2j.require_runs(bad)


class FingerprintContractTests(unittest.TestCase):
    """Pin the recipe-v1 cross-producer fingerprint contract from the consumer side.

    The CLI (NV-4411, cli/pkg/sarif/fingerprint.go) and the backend (NV-4417,
    nimbler_django/issue/fingerprint.py) emit these exact lowercase-hex values in
    properties["nightvision-fingerprint"]. This importer must dedup on that value
    verbatim, so a finding from either producer maps to the same Jira ticket. These
    vectors are frozen; changing them is a coordinated breaking recipe bump across
    all three repos.
    """

    GOLDEN_FINGERPRINTS = (
        "41ac5998fac68d373ed7982da071deb62de802038cde6d618d4ad6bb70d72ed6",
        "097cf680a80a7e772291c4863683053ff15f806fbe12ced91e271bff40c4de6a",
    )

    def test_durable_fingerprint_used_verbatim(self):
        for fp in self.GOLDEN_FINGERPRINTS:
            r = make_result("SQL Injection", endpoint="/api/orders", fingerprint=fp)
            key, scheme = s2j.correlation_key(r)
            self.assertEqual(scheme, "fingerprint")
            # Consumed as-is: a clean recipe-v1 hex is already label/JQL-safe, so it
            # must NOT be re-hashed - otherwise this importer would dedup on a
            # different key than the producer emitted, splitting the ticket.
            self.assertEqual(key, fp)
            self.assertEqual(s2j.normalize_key(fp), fp)
            self.assertEqual(s2j.fp_label(key), s2j.FP_LABEL_PREFIX + fp)


class JqlSafetyTests(unittest.TestCase):
    """A producer fingerprint is producer-supplied, so it must not break out of the
    JQL label literal in the dedup search."""

    def test_hostile_fingerprint_cannot_inject_jql(self):
        hostile = 'evil" OR project = "ADMIN'
        sarif = make_sarif([
            make_result("SQLi", endpoint="/a", risk="HIGH", fingerprint=hostile)])
        jira = JQLRecordingJira()
        common = dict(
            project_id="1", issue_type="Task", component_id=None,
            valid_priorities={"High"}, sleep_fn=silent, log=silent)
        s2j.import_findings(jira, sarif, **common)
        # Second run with the same finding must dedup, proving the label written and
        # the label searched are the same safe normalized value.
        counts = s2j.import_findings(jira, sarif, **common)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(len(jira.created), 1)
        # Every search embeds only the safe normalized label; no injected operator
        # survives into the JQL.
        self.assertTrue(jira.queries)
        for jql in jira.queries:
            m = re.search(r'labels = "([^"]+)"', jql)
            self.assertIsNotNone(m)
            self.assertRegex(m.group(1), r"^" + re.escape(s2j.FP_LABEL_PREFIX) + r"[a-f0-9]{64}$")
            self.assertNotIn("OR project", jql)


class FailureIsolationTests(unittest.TestCase):
    def test_one_finding_failure_does_not_abort_the_run(self):
        sarif = make_sarif([
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="fp-1"),
            make_result("Verbose Banner", endpoint="/api/info", risk="LOW", fingerprint="fp-2"),
        ])
        jira = OneCreateFailsJira("SQL Injection")
        counts = s2j.import_findings(
            jira, sarif, project_id="1", issue_type="Task", component_id=None,
            valid_priorities={"Highest", "Low"}, sleep_fn=silent, log=silent)
        # The failing create is counted and isolated; the other finding still lands.
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(jira.created), 1)
        self.assertEqual(jira.created[0]["summary"], "Verbose Banner at /api/info")

    def test_in_report_duplicate_of_create_failure_is_not_retried(self):
        # Same correlation key twice with a failing create: the duplicate must be
        # caught by in-report dedup (one failure, not two), symmetric with the
        # search-failure path.
        sarif = make_sarif([
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="dup"),
            make_result("SQL Injection", endpoint="/api/orders", risk="CRITICAL", fingerprint="dup"),
        ])
        jira = OneCreateFailsJira("SQL Injection")
        counts = s2j.import_findings(
            jira, sarif, project_id="1", issue_type="Task", component_id=None,
            valid_priorities={"Highest"}, sleep_fn=silent, log=silent)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(counts["created"], 0)


class AdfRenderingTests(unittest.TestCase):
    """to_adf converts Markdown descriptions to ADF so they render in Jira (NV-4414)."""

    def _para_nodes(self, doc, index=0):
        self.assertEqual(doc["type"], "doc")
        self.assertEqual(doc["version"], 1)
        return doc["content"][index]["content"]

    def test_plain_text_is_one_paragraph(self):
        doc = s2j.to_adf("just text")
        self.assertEqual(len(doc["content"]), 1)
        self.assertEqual(self._para_nodes(doc), [{"type": "text", "text": "just text"}])

    def test_bold_becomes_strong_mark(self):
        nodes = self._para_nodes(s2j.to_adf("a **bold** word"))
        strong = [n for n in nodes if n.get("marks") == [{"type": "strong"}]]
        self.assertEqual(strong, [{"type": "text", "text": "bold", "marks": [{"type": "strong"}]}])

    def test_inline_code_becomes_code_mark(self):
        nodes = self._para_nodes(s2j.to_adf("set `Cross-Origin-Resource-Policy` header"))
        code = [n for n in nodes if n.get("marks") == [{"type": "code"}]]
        self.assertEqual(code[0]["text"], "Cross-Origin-Resource-Policy")

    def test_markdown_link_uses_link_mark_and_text(self):
        nodes = self._para_nodes(s2j.to_adf("see [the docs](https://example.com/x) now"))
        link = [n for n in nodes if any(m.get("type") == "link" for m in n.get("marks", []))][0]
        self.assertEqual(link["text"], "the docs")
        self.assertEqual(link["marks"][0]["attrs"]["href"], "https://example.com/x")

    def test_bare_url_becomes_link(self):
        nodes = self._para_nodes(s2j.to_adf("here: https://test.nightvision.net/scans/1/findings/2"))
        link = [n for n in nodes if any(m.get("type") == "link" for m in n.get("marks", []))][0]
        self.assertEqual(link["text"], "https://test.nightvision.net/scans/1/findings/2")
        self.assertEqual(link["marks"][0]["attrs"]["href"], link["text"])

    def test_bare_url_strips_trailing_sentence_punctuation(self):
        nodes = self._para_nodes(s2j.to_adf("see https://test.nightvision.net/findings/2."))
        link = [n for n in nodes if any(m.get("type") == "link" for m in n.get("marks", []))][0]
        self.assertEqual(link["text"], "https://test.nightvision.net/findings/2")
        self.assertEqual(link["marks"][0]["attrs"]["href"], "https://test.nightvision.net/findings/2")
        # the trailing period survives as plain text, not part of the URL
        self.assertTrue(any("." in n.get("text", "") and not n.get("marks") for n in nodes))

    def test_bullet_list_block(self):
        doc = s2j.to_adf("Refs:\n\n- https://a.example\n- https://b.example")
        kinds = [b["type"] for b in doc["content"]]
        self.assertIn("bulletList", kinds)
        bullet = next(b for b in doc["content"] if b["type"] == "bulletList")
        self.assertEqual(len(bullet["content"]), 2)
        self.assertEqual(bullet["content"][0]["type"], "listItem")

    def test_blank_line_splits_paragraphs(self):
        doc = s2j.to_adf("first para\n\nsecond para")
        paras = [b for b in doc["content"] if b["type"] == "paragraph"]
        self.assertEqual(len(paras), 2)

    def test_empty_text_yields_empty_paragraph(self):
        doc = s2j.to_adf("   ")
        self.assertEqual(doc["content"], [{"type": "paragraph", "content": []}])

    def test_build_issue_dict_description_is_adf(self):
        result = make_result("SQLi", endpoint="/x", risk="HIGH")
        fields = s2j.build_issue_dict(result, {}, "1", "Task", None, {"High"}, ["nightvision"])
        self.assertIsInstance(fields["description"], dict)
        self.assertEqual(fields["description"]["type"], "doc")


if __name__ == "__main__":
    unittest.main()
