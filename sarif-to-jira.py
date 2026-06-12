import argparse
import hashlib
import json
import re
import sys
import time

from envdefault import EnvDefault

# The jira package is an optional import so the pure helpers in this module
# (correlation keys, severity mapping, SARIF parsing) can be imported and unit
# tested without it installed. JIRAError is referenced by the retry helper, so a
# minimal stand-in is provided when the package is absent.
try:
    from jira import JIRA, JIRAError
except ImportError:  # pragma: no cover - exercised only without the jira package
    JIRA = None

    class JIRAError(Exception):
        def __init__(self, text="", status_code=None):
            super().__init__(text)
            self.text = text
            self.status_code = status_code


# Correlation labels used to dedup findings across runs (NV-4419).
# Every NightVision-created ticket carries NV_LABEL plus FP_LABEL_PREFIX + <key>,
# where <key> is the durable SARIF fingerprint when present and a best-effort hash
# otherwise. Before creating a ticket we search Jira for the per-finding label and
# skip if it already exists.
NV_LABEL = "nightvision"
# Spelled out ("nv-fp" would read as "false positive" in a findings context).
FP_LABEL_PREFIX = "nv-fingerprint:"

# NUL separator for the best-effort key: it cannot appear in any joined field, so
# the concatenation is unambiguous and a uri/endpoint cannot forge a cross-field
# collision. This mirrors the CLI's durable fingerprint construction.
KEY_SEPARATOR = "\x00"

# Map NightVision risk (SARIF properties.nightvision-risk) to a Jira priority name.
# The mapped name is only applied if the target Jira's priority scheme actually
# defines it; otherwise priority is omitted rather than failing the create.
PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}


# ---------------------------------------------------------------------------------------------------------------------
# Pure SARIF helpers (no Jira dependency; unit tested)
# ---------------------------------------------------------------------------------------------------------------------

def require_runs(sarif_data):
    """Raise ValueError if the document is not SARIF-shaped (no top-level 'runs' list).

    iter_results stays tolerant of partial structures so it remains a pure, unit-testable
    helper; main() calls this to fail fast on a valid-JSON-but-not-SARIF file (a stub
    placeholder, or a broken scan that wrote '{}'), restoring the pre-helper behavior where
    direct indexing raised and the run exited non-zero instead of reporting processed=0.
    """
    if not isinstance(sarif_data, dict) or not isinstance(sarif_data.get("runs"), list):
        raise ValueError("input is not a SARIF report (no top-level 'runs' array)")


def iter_results(sarif_data):
    """Yield (run, result) pairs for every finding in the SARIF document."""
    for run in sarif_data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            yield run, result


def extract_kind_name(result):
    """The finding's vulnerability class. The CLI emits Kind.Name as message.text."""
    text = (result.get("message") or {}).get("text")
    if text:
        return text
    return result.get("ruleId") or ""


def extract_endpoint(result):
    """The endpoint URL path, carried in the region message as 'Found on endpoint <path>'."""
    prefix = "Found on endpoint "
    for loc in result.get("locations", []) or []:
        region = (loc.get("physicalLocation") or {}).get("region") or {}
        text = (region.get("message") or {}).get("text") or ""
        if text.startswith(prefix):
            return text[len(prefix):].strip()
    return None


def extract_location(result):
    """Return (file_uri, start_line) from the first physical location, or (None, None)."""
    locs = result.get("locations") or []
    if not locs:
        return None, None
    phys = locs[0].get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri")
    start_line = (phys.get("region") or {}).get("startLine")
    return uri, start_line


def extract_risk(result):
    return (result.get("properties") or {}).get("nightvision-risk")


def best_effort_key(result):
    """A stable-ish correlation hash for SARIF that lacks the durable fingerprint.

    Derived from identity-ish fields available without the producer's fingerprint:
    kind name, source file uri, start line, and endpoint path. This is an interim
    key (NV-4419); once the producer emits properties.nightvision-fingerprint
    (NV-4411 CLI, NV-4417 backend) correlation_key prefers that durable value and
    NV-4414 retargets fully onto it.
    """
    uri, start_line = extract_location(result)
    basis = KEY_SEPARATOR.join([
        extract_kind_name(result) or "",
        uri or "",
        str(start_line) if start_line is not None else "",
        extract_endpoint(result) or "",
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


# A correlation key is embedded both in a Jira label and in an unescaped JQL string
# literal, so it must be a safe, bounded charset. The best-effort key is already hex;
# a producer fingerprint is producer-supplied, so anything outside this allowlist (or
# over-long) is replaced by its SHA-256 hex - keeping labels and the dedup search
# correct for any producer.
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def normalize_key(raw):
    """Return a Jira-label-safe, JQL-safe form of a correlation key."""
    if _SAFE_KEY_RE.match(raw):
        return raw
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def correlation_key(result):
    """Return (key, scheme). Prefer the durable producer fingerprint; else best-effort.

    Preferring properties.nightvision-fingerprint means CLI-produced SARIF already
    uses the exact key NV-4414 will, so there is no duplicate ticket at the
    Phase 0 -> Phase 1 transition for those findings. A blank/whitespace-only fingerprint is treated as
    absent (falls back to best-effort); any present value is normalized to a safe key.
    """
    fingerprint = (result.get("properties") or {}).get("nightvision-fingerprint")
    if fingerprint and fingerprint.strip():
        return normalize_key(fingerprint.strip()), "fingerprint"
    return best_effort_key(result), "best-effort"


def fp_label(key):
    return FP_LABEL_PREFIX + key


def build_labels(key):
    return [NV_LABEL, fp_label(key)]


def map_priority(risk):
    """Map a NightVision risk to a Jira priority name, or None if unmapped."""
    if not risk:
        return None
    return PRIORITY_MAP.get(risk.upper())


def positive_int(value):
    """argparse type for a 1-or-greater integer (used by --max-issues).

    A zero or negative cap would make the --max-issues guard true on the first
    iteration and silently process nothing with exit 0, so reject it at parse time.
    """
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be a positive integer (got {})".format(value))
    return n


def build_summary(result):
    """A distinguishable title: vulnerability class plus endpoint when known.

    This stays lightweight; NV-4414 adds the HTTP method and richer
    formatting once it consumes the durable fingerprint.
    """
    kind = extract_kind_name(result) or "NightVision finding"
    endpoint = extract_endpoint(result)
    if endpoint:
        return "{} at {}".format(kind, endpoint)
    return kind


def get_description(result, run):
    """The rule's full description text, looked up by ruleId (existing behaviour)."""
    rule_id = result.get("ruleId")
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    for rule in rules:
        if rule.get("id") == rule_id:
            full = rule.get("fullDescription") or {}
            if full.get("text"):
                return full["text"]
    # Fall back to the finding message so the ticket is never bodyless.
    return (result.get("message") or {}).get("text") or "No description available."


def build_issue_dict(result, run, project_id, issue_type, component_id, valid_priorities, labels):
    """Assemble the Jira create payload for a single finding."""
    fields = {
        "project": {"id": str(project_id)},
        "summary": build_summary(result),
        "description": get_description(result, run),
        "issuetype": {"name": issue_type},
        "labels": labels,
    }
    if component_id:
        fields["components"] = [{"id": component_id}]

    priority = map_priority(extract_risk(result))
    # Only set priority when the target scheme actually defines the mapped name,
    # so a renamed/limited priority scheme omits it rather than failing the create.
    if priority and valid_priorities and priority in valid_priorities:
        fields["priority"] = {"name": priority}
    return fields


# ---------------------------------------------------------------------------------------------------------------------
# Jira interaction (thin wrappers, retried on 429)
# ---------------------------------------------------------------------------------------------------------------------

def _retry_on_429(fn, max_retries=5, sleep_fn=time.sleep):
    """Call fn(), retrying with exponential backoff on HTTP 429 (rate limit)."""
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except JIRAError as e:
            status = getattr(e, "status_code", None)
            if status == 429 and attempt < max_retries:
                sleep_fn(min(2 ** attempt, 30))
                continue
            raise
    # Unreachable: every path above returns or raises. Defensive guard so a future
    # edit (e.g. a `continue` on the final attempt) cannot silently return None.
    raise RuntimeError("retry loop exhausted without returning")


def resolve_valid_issue_types(jira):
    """Return the set of issue type names, or None if it cannot be determined."""
    try:
        return {t.name for t in jira.issue_types()}
    except Exception:
        return None


def resolve_valid_priorities(jira):
    """Return the set of priority names in the Jira scheme, or None if unavailable."""
    try:
        return {p.name for p in jira.priorities()}
    except Exception:
        return None


def find_existing(jira, project_id, label_value, max_retries=5, sleep_fn=time.sleep):
    """True if a ticket in the project already carries the per-finding fp label."""
    jql = 'project = "{}" AND labels = "{}"'.format(project_id, label_value)
    issues = _retry_on_429(
        lambda: jira.search_issues(jql, maxResults=1),
        max_retries=max_retries,
        sleep_fn=sleep_fn,
    )
    return len(issues) > 0


def create_issue(jira, fields, max_retries=5, sleep_fn=time.sleep):
    return _retry_on_429(
        lambda: jira.create_issue(fields=fields),
        max_retries=max_retries,
        sleep_fn=sleep_fn,
    )


# ---------------------------------------------------------------------------------------------------------------------
# Import loop
# ---------------------------------------------------------------------------------------------------------------------

def import_findings(jira, sarif_data, project_id, issue_type, component_id,
                    valid_priorities, dry_run=False, max_issues=None,
                    max_retries=5, sleep_fn=time.sleep, log=print):
    """Create one deduped Jira ticket per finding. Resilient and resumable.

    Per-finding failures are logged and counted; they do not abort the run, so a
    re-run resumes (already-created findings are skipped via their fp label).
    """
    counts = {"seen": 0, "created": 0, "planned": 0, "skipped": 0, "failed": 0}
    seen_keys = set()

    for run, result in iter_results(sarif_data):
        if max_issues is not None and (counts["created"] + counts["planned"]) >= max_issues:
            log("Reached --max-issues={}; stopping.".format(max_issues))
            break

        counts["seen"] += 1
        key, scheme = correlation_key(result)
        label_value = fp_label(key)

        # Dedup within this single SARIF file (identical findings emitted twice).
        if key in seen_keys:
            counts["skipped"] += 1
            log("Skip (duplicate within report) {}: {}".format(scheme, build_summary(result)))
            continue

        try:
            if find_existing(jira, project_id, label_value, max_retries, sleep_fn):
                counts["skipped"] += 1
                seen_keys.add(key)
                log("Skip (already in Jira) {}: {}".format(label_value, build_summary(result)))
                continue
        except JIRAError as e:
            counts["failed"] += 1
            # Mark the key seen so a duplicate of this finding later in the same
            # report is not re-searched and counted as a second failure.
            seen_keys.add(key)
            log("Error searching for {}: {}".format(label_value, getattr(e, "text", e)))
            continue

        fields = build_issue_dict(
            result, run, project_id, issue_type, component_id,
            valid_priorities, build_labels(key),
        )

        if dry_run:
            counts["planned"] += 1
            seen_keys.add(key)
            log("DRY-RUN would create [{}] {}".format(
                fields.get("priority", {}).get("name", "-"), fields["summary"]))
            continue

        try:
            new_issue = create_issue(jira, fields, max_retries, sleep_fn)
            counts["created"] += 1
            seen_keys.add(key)
            log("Issue created: {} ({})".format(new_issue.key, fields["summary"]))
        except JIRAError as e:
            counts["failed"] += 1
            # Mark the key seen for the same reason as the search-failure path
            # above: a duplicate of this finding later in the report should not be
            # re-attempted and counted as a second failure.
            seen_keys.add(key)
            log("Error creating issue for {}: {}".format(fields["summary"], getattr(e, "text", e)))

    return counts


def main(args):
    # Jira server credentials
    jira_url = args.url
    jira_user_email = args.email
    jira_api_token = args.token

    assert jira_url, "JIRA_URL not specified."
    assert jira_user_email, "JIRA_USER_EMAIL not specified."
    assert jira_api_token, "JIRA_API_TOKEN not specified."

    # Jira Issue properties
    jira_project_id = args.project
    jira_issue_type = args.type
    jira_component_name = args.component

    assert jira_project_id, "JIRA_PROJECT_ID not specified."

    if JIRA is None:
        raise RuntimeError("The 'jira' package is required to talk to Jira. Run: pip install jira")

    # Connect to Jira. Note: --dry-run still connects and queries Jira (to classify
    # each finding as would-create vs would-skip); it only suppresses ticket creation.
    if args.dry_run:
        print("DRY-RUN: connecting to Jira to classify findings; no issues will be created.")
    jira = JIRA(
        basic_auth=(jira_user_email, jira_api_token), options={"server": jira_url}
    )

    # Fail fast on configuration errors, before iterating findings.
    # Check if Project exists
    try:
        jira.project(id=jira_project_id)
    except JIRAError as e:
        raise ValueError(e.text)

    # Get component id
    component_id = None
    if jira_component_name:
        components = jira.project_components(jira_project_id)
        matched_components = list(
            filter(lambda c: c.name == jira_component_name, components)
        )
        if len(matched_components) == 0:
            raise ValueError(f"Component '{jira_component_name}' not found in Jira.")
        component_id = matched_components[0].id

    # Validate the issue type up front (fail fast, not mid-loop).
    valid_issue_types = resolve_valid_issue_types(jira)
    if valid_issue_types is not None and jira_issue_type not in valid_issue_types:
        raise ValueError(
            "Issue type '{}' not available. Valid types: {}".format(
                jira_issue_type, ", ".join(sorted(valid_issue_types)))
        )

    # Resolve the priority scheme once; used to decide whether to set priority.
    valid_priorities = resolve_valid_priorities(jira)
    if valid_priorities is None:
        print("WARNING: could not read the Jira priority scheme; tickets will be created "
              "without a priority.")
    elif not valid_priorities:
        print("WARNING: the Jira priority scheme is empty; tickets will be created "
              "without a priority.")

    # Load SARIF data
    sarif_file = args.sarif_file
    try:
        with open(sarif_file, "r") as file:
            sarif_data = json.load(file)
    except OSError:
        raise ValueError(f"Could not read a file '{sarif_file}'")

    require_runs(sarif_data)

    counts = import_findings(
        jira, sarif_data,
        project_id=jira_project_id,
        issue_type=jira_issue_type,
        component_id=component_id,
        valid_priorities=valid_priorities,
        dry_run=args.dry_run,
        max_issues=args.max_issues,
    )

    # "processed" is findings reached before any --max-issues cap, not the report
    # total; a capped run also logs "Reached --max-issues=N" above.
    print(
        "Done. processed={seen} created={created} planned(dry-run)={planned} "
        "skipped={skipped} failed={failed}".format(**counts)
    )
    # Non-zero exit if any finding failed, so CI notices; skips are not failures.
    if counts["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python sarif-to-jira.py",
        description="Create Jira tickets from a NightVision SARIF report (deduped, severity-mapped).",
    )

    group_jira = parser.add_argument_group("Jira server credentials")
    group_jira.add_argument(
        "--url", action=EnvDefault, envvar="JIRA_URL", dest="url",
        help="Jira server URL",
    )
    group_jira.add_argument(
        "--email", action=EnvDefault, envvar="JIRA_USER_EMAIL", dest="email",
        help="Jira user email",
    )
    group_jira.add_argument(
        "--token", action=EnvDefault, envvar="JIRA_API_TOKEN", dest="token",
        help="Jira API token",
    )

    group_issue = parser.add_argument_group("Issue properties")
    group_issue.add_argument(
        "-p", "--project-id", action=EnvDefault, envvar="JIRA_PROJECT_ID", dest="project", metavar="PROJECT-ID",
        help="Jira Project ID"
    )
    group_issue.add_argument(
        "-i", "--issue-type", action=EnvDefault, envvar="JIRA_ISSUE_TYPE", dest="type", default="Task",
        help="Issue type - defaults to 'Task'",
    )
    group_issue.add_argument(
        "-c", "--component", action=EnvDefault, envvar="JIRA_COMPONENT", dest="component", default="",
        help="Issue component",
    )

    group_run = parser.add_argument_group("Run options")
    group_run.add_argument(
        "--sarif-file", dest="sarif_file", default="results.sarif",
        help="Path to the SARIF report - defaults to 'results.sarif'",
    )
    group_run.add_argument(
        "--dry-run", dest="dry_run", action="store_true",
        help="Report what would be created without creating any Jira issues "
             "(still connects to Jira and searches per finding to classify create vs skip)",
    )
    group_run.add_argument(
        "--max-issues", dest="max_issues", type=positive_int, default=None, metavar="N",
        help="Stop after N issues are created (in dry-run, after N would be created)",
    )

    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
