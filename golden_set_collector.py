#!/usr/bin/env python3
"""
DevRER golden-set collector
===========================

Builds a labelling-ready dataset of CI failures from GitHub Actions history.
Read-only: it only calls GET endpoints. Needs `Actions: read` (+ Metadata: read)
on the repos you list. Use a fine-grained token or a GitHub App installation
token limited to those repos. Token is read from GITHUB_TOKEN / GH_TOKEN, or
from `gh auth token` if the gh CLI is installed.

Commands
--------
  inventory   Count failed runs / failed steps per repo (no log downloads).
              Run this FIRST: it shows your real class mix and what is scarce.
  collect     Download failed-job logs, redact, extract an error-centred
              excerpt, compute a failure signature and weak hints, and append
              records to <out>/raw_candidates.jsonl (resumable).
  split       Cap duplicates per signature, split dev/test with signature-level
              isolation (+ optional hold-out repos), emit an annotation CSV
              and a coverage report.
  selftest    Offline checks for redaction, excerpting and signatures.

Typical flow
------------
  export GITHUB_TOKEN=...            # read-only token
  python golden_set_collector.py inventory --repos-file repos.txt --days 90
  python golden_set_collector.py collect   --repos-file repos.txt --days 90 \
         --include-recovered --max-records 20 --out data      # small trial first
  python golden_set_collector.py collect   --repos-file repos.txt --days 90 \
         --include-recovered --out data                       # full run
  python golden_set_collector.py split --in data/raw_candidates.jsonl \
         --holdout-repos org/service-x,org/service-y --out data

repos.txt: one "owner/repo" per line; '#' starts a comment.

IMPORTANT
---------
* Redaction is regex-based best effort, NOT a guarantee. Treat the output as
  confidential, spot-check it, and keep it in a restricted location.
* The "heuristic_hint" field exists only for coverage counting and stratified
  sampling. It is NOT a label. Gold labels come from human reviewers.
* Not tested against the live GitHub API from the authoring environment.
  Do a small trial (--max-records 20) and inspect the output before a full run.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

API_DEFAULT = "https://api.github.com"
FAILED_CONCLUSIONS = {"failure", "timed_out"}
SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
def _kv_sub(m: "re.Match[str]") -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}<REDACTED:SECRET>{m.group(3)}"


def _hdr_sub(m: "re.Match[str]") -> str:
    return f"{m.group(1)}<REDACTED:AUTH>"


# (name, compiled regex, replacement string or callable)
REDACTIONS: list[tuple[str, "re.Pattern[str]", Any]] = [
    ("private_key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<REDACTED:PRIVATE_KEY>"),
    ("github_token",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"),
     "<REDACTED:GITHUB_TOKEN>"),
    ("aws_access_key",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
     "<REDACTED:AWS_KEY_ID>"),
    ("slack_token",
     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
     "<REDACTED:SLACK_TOKEN>"),
    ("sonar_token",
     re.compile(r"\b(?:squ|sqp|sqa)_[A-Fa-f0-9]{40}\b"),
     "<REDACTED:SONAR_TOKEN>"),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "<REDACTED:JWT>"),
    ("auth_header",
     re.compile(r"(?i)(\bauthorization:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]+"),
     _hdr_sub),
    ("url_credentials",
     re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),
     "<REDACTED:URL_CREDENTIALS>"),
    ("kv_secret",
     re.compile(
         r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|"
         r"access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)(['\"]?)"
         r"(?!<REDACTED)([^\s'\"]{4,})\3"),
     _kv_sub),
    ("email",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "<REDACTED:EMAIL>"),
]

# Optional, noisier: any long mixed alphanumeric token (hashes of secrets, API keys
# without a recognisable prefix). May also mask legitimate digests.
AGGRESSIVE = re.compile(r"\b(?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Za-z])[A-Za-z0-9+/_=-]{32,}\b")


def redact(text: str, aggressive: bool = False) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for name, rx, repl in REDACTIONS:
        text, n = rx.subn(repl, text)
        if n:
            counts[name] = n
    if aggressive:
        text, n = AGGRESSIVE.subn("<REDACTED:LONG_TOKEN>", text)
        if n:
            counts["long_token"] = n
    return text, counts


# --------------------------------------------------------------------------- #
# Log analysis: excerpt, primary error, signature, weak hints
# --------------------------------------------------------------------------- #
TS_RE = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
GENERIC_EXIT_RE = re.compile(r"^process completed with exit code \d+\.?$", re.I)
ERROR_KW_RE = re.compile(
    r"\b(error|failed|failure|exception|fatal|cannot|can't|unable|denied|refused|"
    r"timed? ?out|not found|traceback)\b", re.I)


def preprocess(text: str) -> list[str]:
    out = []
    for ln in text.splitlines():
        ln = ANSI_RE.sub("", TS_RE.sub("", ln))
        out.append(ln.rstrip())
    return out


def analyze_log(lines: list[str], max_chars: int) -> dict[str, Any]:
    """Return error annotations, the primary error line and an error-centred excerpt."""
    messages = [(i, l[len("##[error]"):].strip())
                for i, l in enumerate(lines) if l.startswith("##[error]")]
    primary: Optional[tuple[int, str]] = None

    if messages:
        anchor = messages[0][0]
        first_msg = messages[0][1]
        if not GENERIC_EXIT_RE.match(first_msg):
            primary = messages[0]
        else:
            # "Process completed with exit code N" is the end of the failing step;
            # the real error is a few lines earlier in the same step.
            for j in range(anchor - 1, max(-1, anchor - 200), -1):
                l = lines[j]
                if not l.startswith("##[") and l.strip() and ERROR_KW_RE.search(l):
                    primary = (j, l.strip())
                    break
            if primary is None:
                for i, msg in messages[1:]:
                    if not GENERIC_EXIT_RE.match(msg):
                        primary = (i, msg)
                        break
            if primary is None:
                primary = messages[0]
        before, after = 80, 6
    else:
        anchor = max(0, len(lines) - 1)
        for j in range(anchor, max(-1, anchor - 150), -1):
            l = lines[j]
            if l.strip() and ERROR_KW_RE.search(l):
                primary = (j, l.strip())
                anchor = j
                break
        before, after = 120, 10

    start = max(0, anchor - before)
    end = min(len(lines), anchor + after + 1)
    seg = [l for l in lines[start:end]]
    if not any(l.startswith("##[group]") for l in seg):
        for j in range(start - 1, max(-1, start - 400), -1):
            if lines[j].startswith("##[group]"):
                seg.insert(0, lines[j])
                break
    # collapse runs of blank lines
    compact: list[str] = []
    for l in seg:
        if l.strip() == "" and compact and compact[-1].strip() == "":
            continue
        compact.append(l)
    excerpt = "\n".join(compact)
    truncated = False
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
        excerpt = excerpt[excerpt.find("\n") + 1:] if "\n" in excerpt else excerpt
        excerpt = "[...excerpt truncated...]\n" + excerpt
        truncated = True

    return {
        "total_lines": len(lines),
        "error_lines": [m[:300] for _, m in messages[:10]],
        "primary_error": (primary[1][:400] if primary else ""),
        "excerpt": excerpt,
        "excerpt_truncated": truncated,
    }


_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_HEX = re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{7,64}\b")
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?z?")
_PATH = re.compile(r"(?:[a-z]:)?(?:[/\\][\w.@+-]+){2,}")
_NUM = re.compile(r"\b\d+(?:\.\d+)*\b")
_WS = re.compile(r"\s+")


def normalize_text(s: str) -> str:
    s = ANSI_RE.sub("", s.lower())
    s = _UUID.sub("<uuid>", s)
    s = _ISO_TS.sub("<ts>", s)
    s = _HEX.sub("<hex>", s)
    s = _PATH.sub("<path>", s)
    s = _NUM.sub("<n>", s)
    return _WS.sub(" ", s).strip()[:300]


def make_signature(primary_error: str, failed_step: Optional[str]) -> tuple[str, str]:
    """Stable across repos/runs: normalised error text + normalised step name.
    Repo is intentionally NOT part of the signature (cross-repo grouping)."""
    step = normalize_text(failed_step or "unknown-step")
    text = normalize_text(primary_error or "no-error-line")
    sig_text = f"{step} | {text}"
    return hashlib.sha1(sig_text.encode()).hexdigest()[:12], sig_text


# Weak hints for COVERAGE COUNTING ONLY. Overlaps are expected and informative
# (e.g. a network failure while resolving dependencies matches two buckets - your
# labelling guide must decide such cases).
HINT_PATTERNS: dict[str, "re.Pattern[str]"] = {
    "CODE_QUALITY?": re.compile(r"quality gate|sonar(?:qube|cloud)?.{0,80}(?:fail|error)|sonar.{0,40}gate", re.I),
    "VULNERABILITY?": re.compile(r"\bsnyk\b|vulnerabilit|\bCVE-\d{4}-\d+|high severity|critical severity", re.I),
    "BUILD_DEPENDENCY?": re.compile(
        r"could not resolve dependenc|dependency resolution|cannot find module|no matching distribution|"
        r"npm err! (?:404|code e404)|compilation (?:error|failure)|cannot find symbol|failed to solve|"
        r"pull access denied|could not find artifact|package .{0,60} not found|failed to execute goal|"
        r"module .{0,60} not found|error: cannot find", re.I),
    "TEST_FAILURE?": re.compile(
        r"tests run:.{0,60}failures: [1-9]|\b\d+ (?:tests? )?failed\b|assertionerror|assertion failed|"
        r"\bFAIL\b\s+\S+|failed tests|there were test failures|expected .{0,60} but (?:was|got)", re.I),
    "INFRA_FLAKY?": re.compile(
        r"econnreset|etimedout|connection reset|connection timed out|could not resolve host|"
        r"temporary failure in name resolution|503 service unavailable|502 bad gateway|"
        r"toomanyrequests|rate limit|i/o timeout|tls handshake timeout|no space left on device|"
        r"the runner has received a shutdown signal|lost communication with the server|"
        r"the operation was canceled|received request to deprovision", re.I),
    "CONFIG_OR_PERMISSION?": re.compile(
        r"invalid workflow file|yaml.{0,40}(?:error|invalid)|resource not accessible by integration|"
        r"permission denied|access ?denied|not authorized|unauthorized|no basic auth credentials|"
        r"accessdeniedexception|\bdenied:|context access might be invalid|secret .{0,40} not (?:set|found)", re.I),
}


def heuristic_hints(excerpt: str, error_lines: list[str]) -> list[str]:
    blob = excerpt + "\n" + "\n".join(error_lines)
    hits = [name for name, rx in HINT_PATTERNS.items() if rx.search(blob)]
    return hits or ["NO_HINT"]


# --------------------------------------------------------------------------- #
# GitHub client (read-only)
# --------------------------------------------------------------------------- #
def resolve_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok
    if shutil.which("gh"):
        try:
            out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:
            pass
    sys.exit("No token found. Set GITHUB_TOKEN (read-only, Actions:read) or run `gh auth login`.")


class GitHubClient:
    def __init__(self, token: str, api_url: str = API_DEFAULT, verbose: bool = False):
        import requests  # imported lazily so selftest/split work without it

        self.requests = requests
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "devrer-golden-set-collector",
        })
        self.api = api_url.rstrip("/")
        self.verbose = verbose
        self.calls = 0

    def _sleep_until(self, reset: Optional[str], default: int = 60) -> None:
        wait = default
        if reset and reset.isdigit():
            wait = max(1, int(reset) - int(time.time()) + 2)
        print(f"  [rate limit] sleeping {wait}s", file=sys.stderr)
        time.sleep(min(wait, 3700))

    def request(self, path_or_url: str, params: Optional[dict] = None, stream: bool = False,
                ok: tuple[int, ...] = (200,)):
        url = path_or_url if path_or_url.startswith("http") else f"{self.api}{path_or_url}"
        for attempt in range(6):
            try:
                resp = self.s.get(url, params=params, stream=stream, timeout=60)
            except self.requests.RequestException as e:
                if attempt == 5:
                    raise
                time.sleep(2 ** attempt)
                print(f"  [retry] network error {e!r}", file=sys.stderr)
                continue
            self.calls += 1
            remaining = resp.headers.get("X-RateLimit-Remaining")
            reset = resp.headers.get("X-RateLimit-Reset")
            if resp.status_code in (403, 429):
                retry_after = resp.headers.get("Retry-After")
                limited = (remaining == "0") or retry_after or "rate limit" in resp.text.lower()
                if limited:
                    if retry_after and retry_after.isdigit():
                        time.sleep(int(retry_after) + 1)
                    else:
                        self._sleep_until(reset)
                    continue
            if resp.status_code >= 500:
                time.sleep(2 ** attempt)
                continue
            if resp.status_code in ok:
                if remaining and remaining.isdigit() and int(remaining) < 20:
                    self._sleep_until(reset)
                return resp
            resp.raise_for_status()
        raise RuntimeError(f"GET {url} failed after retries")

    def get_json(self, path: str, params: Optional[dict] = None) -> Any:
        return self.request(path, params).json()

    def paginate(self, path: str, key: str, params: Optional[dict] = None, max_pages: int = 50) -> Iterator[dict]:
        params = dict(params or {})
        params["per_page"] = 100
        for page in range(1, max_pages + 1):
            params["page"] = page
            items = self.get_json(path, params).get(key, [])
            yield from items
            if len(items) < 100:
                break

    def job_log(self, repo: str, job_id: int, max_bytes: int) -> tuple[str, str, bool]:
        """Return (status, text, head_truncated). status: ok | expired | missing."""
        resp = self.request(f"/repos/{repo}/actions/jobs/{job_id}/logs", stream=True, ok=(200, 404, 410))
        if resp.status_code == 410:
            return "expired", "", False
        if resp.status_code == 404:
            return "missing", "", False
        buf = bytearray()
        head_truncated = False
        for chunk in resp.iter_content(1 << 20):
            buf.extend(chunk)
            if len(buf) > max_bytes:  # keep the TAIL: failures are near the end
                del buf[: len(buf) - max_bytes]
                head_truncated = True
        return "ok", buf.decode("utf-8", "replace"), head_truncated


# --------------------------------------------------------------------------- #
# Run discovery
# --------------------------------------------------------------------------- #
def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_runs_window(client: GitHubClient, repo: str, start: datetime, end: datetime,
                     min_span: timedelta = timedelta(hours=1)) -> Iterator[dict]:
    """Completed runs created in [start, end]. GitHub caps filtered listings at
    1,000 results, so dense windows are split in half recursively."""
    params = {"status": "completed", "created": f"{iso(start)}..{iso(end)}", "per_page": 100, "page": 1}
    first = client.get_json(f"/repos/{repo}/actions/runs", params)
    total = first.get("total_count", 0)
    if total >= 1000 and (end - start) > min_span:
        mid = start + (end - start) / 2
        yield from list_runs_window(client, repo, start, mid, min_span)
        yield from list_runs_window(client, repo, mid, end, min_span)
        return
    if total >= 1000:
        print(f"  [warn] {repo}: >=1000 runs within {min_span}; some may be missed", file=sys.stderr)
    page_items = first.get("workflow_runs", [])
    yield from page_items
    page = 2
    while len(page_items) == 100 and page <= 10:
        params["page"] = page
        page_items = client.get_json(f"/repos/{repo}/actions/runs", params).get("workflow_runs", [])
        yield from page_items
        page += 1


def fetch_all_runs(client: GitHubClient, repo: str, days: int, workflows: list[str],
                   window_days: int = 7) -> list[dict]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    runs: dict[int, dict] = {}
    cur = since
    while cur < now:
        nxt = min(cur + timedelta(days=window_days), now)
        for r in list_runs_window(client, repo, cur, nxt):
            runs[r["id"]] = r  # windows overlap at boundaries -> dedupe by id
        cur = nxt
    out = list(runs.values())
    if workflows:
        wl = [w.lower() for w in workflows]
        out = [r for r in out if any(w in (r.get("name") or "").lower() for w in wl)]
    return out


def jobs_for_attempt(client: GitHubClient, repo: str, run_id: int, attempt: int) -> list[dict]:
    return list(client.paginate(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs"))


def failed_step(job: dict) -> Optional[str]:
    for st in job.get("steps") or []:
        if st.get("conclusion") == "failure":
            return st.get("name")
    return None


def iter_candidates(client: GitHubClient, repo: str, runs: list[dict], include_recovered: bool,
                    fetch_jobs: bool = True) -> Iterator[dict]:
    """Yield dicts: kind, run, attempt, job (may be None if fetch_jobs=False), evidence."""
    # same workflow + same SHA later succeeded -> weak flaky signal for failed runs
    success_times: dict[tuple, list[str]] = defaultdict(list)
    for r in runs:
        if r.get("conclusion") == "success":
            success_times[(r.get("workflow_id"), r.get("head_sha"))].append(r["created_at"])

    for r in sorted(runs, key=lambda x: x["created_at"]):
        concl = r.get("conclusion")
        attempt = int(r.get("run_attempt") or 1)
        if concl in FAILED_CONCLUSIONS:
            later = any(t > r["created_at"] for t in success_times.get((r.get("workflow_id"), r.get("head_sha")), []))
            evidence = {"attempts_total": attempt, "passed_later_on_same_sha": later}
            if not fetch_jobs:
                yield {"kind": "failed_final", "run": r, "attempt": attempt, "job": None, "evidence": evidence}
                continue
            for job in jobs_for_attempt(client, repo, r["id"], attempt):
                if job.get("conclusion") in FAILED_CONCLUSIONS:
                    yield {"kind": "failed_final", "run": r, "attempt": attempt, "job": job, "evidence": evidence}
        elif concl == "success" and attempt > 1 and include_recovered:
            final_jobs = jobs_for_attempt(client, repo, r["id"], attempt)
            passed_names = {j["name"] for j in final_jobs if j.get("conclusion") == "success"}
            for a in range(1, attempt):
                for job in jobs_for_attempt(client, repo, r["id"], a):
                    if job.get("conclusion") in FAILED_CONCLUSIONS:
                        yield {"kind": "recovered_after_rerun", "run": r, "attempt": a, "job": job,
                               "evidence": {"final_attempt": attempt, "final_conclusion": "success",
                                            "same_job_passed_in_final": job["name"] in passed_names}}


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def load_repos(args) -> list[str]:
    repos = list(args.repos or [])
    if args.repos_file:
        for line in Path(args.repos_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                repos.append(line)
    repos = sorted(set(repos))
    if not repos:
        sys.exit("No repositories given (use --repos or --repos-file).")
    return repos


def make_client(args) -> GitHubClient:
    return GitHubClient(resolve_token(), args.api_url)


def cmd_inventory(args) -> None:
    client = make_client(args)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows: Counter = Counter()
    per_repo: dict[str, Counter] = defaultdict(Counter)
    for repo in load_repos(args):
        print(f"[{repo}] listing runs ({args.days}d)...", file=sys.stderr)
        runs = fetch_all_runs(client, repo, args.days, args.workflow)
        per_repo[repo]["runs_completed"] = len(runs)
        per_repo[repo]["runs_failed"] = sum(1 for r in runs if r.get("conclusion") in FAILED_CONCLUSIONS)
        per_repo[repo]["runs_recovered_after_rerun"] = sum(
            1 for r in runs if r.get("conclusion") == "success" and int(r.get("run_attempt") or 1) > 1)
        for c in iter_candidates(client, repo, runs, args.include_recovered, fetch_jobs=not args.no_jobs):
            step = failed_step(c["job"]) if c["job"] else "(not fetched)"
            wf = c["run"].get("name") or "?"
            rows[(repo, wf, step or "(no failed step recorded)", c["kind"])] += 1
    path = out / "inventory.csv"
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "workflow", "failed_step", "kind", "count"])
        for (repo, wf, step, kind), n in sorted(rows.items(), key=lambda kv: (-kv[1], kv[0])):
            w.writerow([repo, wf, step, kind, n])
    print(f"\n{'repo':45} {'completed':>9} {'failed':>7} {'recovered':>9}")
    for repo, c in per_repo.items():
        print(f"{repo:45} {c['runs_completed']:>9} {c['runs_failed']:>7} {c['runs_recovered_after_rerun']:>9}")
    print(f"\nWrote {path}  (API calls: {client.calls})")
    print("Reminder: GitHub keeps logs ~90 days by default - collect before they expire.")


def record_id(repo: str, run_id: int, attempt: int, job_id: int) -> str:
    return f"{repo}#{run_id}.{attempt}#{job_id}"


def load_seen(path: Path) -> set[str]:
    seen: set[str] = set()
    if path.exists():
        with path.open() as fh:
            for line in fh:
                try:
                    seen.add(json.loads(line)["id"])
                except Exception:
                    continue
    return seen


def build_record(repo: str, cand: dict, log_status: str, log_text: str, head_trunc: bool, args) -> dict:
    run, job = cand["run"], cand["job"]
    step = failed_step(job)
    rec: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": record_id(repo, run["id"], cand["attempt"], job["id"]),
        "source": "real",
        "repo": repo,
        "workflow": run.get("name"),
        "workflow_id": run.get("workflow_id"),
        "run_id": run["id"],
        "run_attempt": cand["attempt"],
        "run_url": run.get("html_url"),
        "job_id": job["id"],
        "job_name": job.get("name"),
        "failed_step": step,
        "head_sha": run.get("head_sha"),
        "branch": run.get("head_branch"),
        "event": run.get("event"),
        "created_at": run.get("created_at"),
        "job_conclusion": job.get("conclusion"),
        "outcome_kind": cand["kind"],
        "flaky_evidence": cand["evidence"],
        "log_status": log_status,
        "log_head_truncated": head_trunc,
        "collected_at": iso(datetime.now(timezone.utc)),
        # --- to be filled by humans ---
        "gold_label": None,
        "subtype": None,
        "ambiguous": None,
        "rationale": None,
        "annotators": [],
        "retry_eligible_expected": None,
        "reference_root_cause": None,
    }
    if log_status == "ok":
        red, counts = redact(log_text, aggressive=args.aggressive)
        lines = preprocess(red)
        info = analyze_log(lines, args.max_excerpt_chars)
        sig, sig_text = make_signature(info["primary_error"], step)
        rec.update({
            "redaction_counts": counts,
            "total_lines": info["total_lines"],
            "error_lines": info["error_lines"],
            "primary_error": info["primary_error"],
            "excerpt": info["excerpt"],
            "excerpt_truncated": info["excerpt_truncated"],
            "signature": sig,
            "signature_text": sig_text,
            "heuristic_hint": heuristic_hints(info["excerpt"], info["error_lines"]),
        })
        if args.save_logs:
            d = Path(args.save_logs)
            d.mkdir(parents=True, exist_ok=True)
            fn = rec["id"].replace("/", "__").replace("#", "_") + ".log.gz"
            with gzip.open(d / fn, "wt", encoding="utf-8") as gz:  # REDACTED full log
                gz.write("\n".join(lines))
            rec["redacted_log_file"] = fn
    else:
        sig, sig_text = make_signature("", step)
        rec.update({"redaction_counts": {}, "total_lines": 0, "error_lines": [], "primary_error": "",
                    "excerpt": "", "excerpt_truncated": False, "signature": sig,
                    "signature_text": sig_text, "heuristic_hint": ["NO_LOG"]})
    return rec


def cmd_collect(args) -> None:
    client = make_client(args)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / "raw_candidates.jsonl"
    seen = load_seen(target)
    new = 0
    status_counts: Counter = Counter()
    with target.open("a", encoding="utf-8") as fh:
        for repo in load_repos(args):
            print(f"[{repo}] listing runs ({args.days}d)...", file=sys.stderr)
            runs = fetch_all_runs(client, repo, args.days, args.workflow)
            for cand in iter_candidates(client, repo, runs, args.include_recovered):
                rid = record_id(repo, cand["run"]["id"], cand["attempt"], cand["job"]["id"])
                if rid in seen:
                    continue
                status, text, head_trunc = client.job_log(repo, cand["job"]["id"], args.max_log_mb * 1024 * 1024)
                rec = build_record(repo, cand, status, text, head_trunc, args)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                seen.add(rid)
                new += 1
                status_counts[status] += 1
                if new % 10 == 0:
                    print(f"  ...{new} records ({dict(status_counts)})", file=sys.stderr)
                if args.max_records and new >= args.max_records:
                    print(f"Reached --max-records={args.max_records}", file=sys.stderr)
                    print(f"Wrote {new} new records to {target} (API calls: {client.calls})")
                    return
    print(f"Wrote {new} new records to {target}  log status: {dict(status_counts)}  (API calls: {client.calls})")


def cap_per_signature(records: list[dict], cap: int) -> list[dict]:
    by_sig: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_sig[r["signature"]].append(r)
    kept: list[dict] = []
    for recs in by_sig.values():
        by_repo: dict[str, list[dict]] = defaultdict(list)
        for r in sorted(recs, key=lambda x: x["created_at"]):
            by_repo[r["repo"]].append(r)
        queues = [by_repo[k] for k in sorted(by_repo)]
        picked: list[dict] = []
        while len(picked) < cap and any(queues):  # round-robin across repos
            for q in queues:
                if q and len(picked) < cap:
                    picked.append(q.pop(0))
        kept.extend(picked)
    return kept


def hash_frac(seed: str, sig: str) -> float:
    return int(hashlib.sha1(f"{seed}:{sig}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


def cmd_split(args) -> None:
    src = Path(args.input)
    out = Path(args.out)
    (out / "splits").mkdir(parents=True, exist_ok=True)
    records = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    total_in = len(records)
    usable = [r for r in records if r.get("log_status") == "ok" and r.get("excerpt")]
    dropped_nolog = total_in - len(usable)
    capped = cap_per_signature(usable, args.max_per_signature)
    holdout = {x.strip() for x in (args.holdout_repos or "").split(",") if x.strip()}
    holdout_sigs = {r["signature"] for r in capped if r["repo"] in holdout}

    dev: list[dict] = []
    test: list[dict] = []
    for r in capped:
        if r["repo"] in holdout:
            r["split"], r["split_reason"] = "test", "holdout_repo"
        elif r["signature"] in holdout_sigs:
            r["split"], r["split_reason"] = "test", "signature_seen_in_holdout_repo"
        elif hash_frac(args.seed, r["signature"]) < args.test_frac:
            r["split"], r["split_reason"] = "test", "signature_hash"
        else:
            r["split"], r["split_reason"] = "dev", "signature_hash"
        (test if r["split"] == "test" else dev).append(r)

    for name, rows in (("dev", dev), ("test", test)):
        with (out / "splits" / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    with (out / "annotation_sheet.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "split", "repo", "failed_step", "outcome_kind", "flaky_evidence", "heuristic_hint",
                    "primary_error", "excerpt", "gold_label", "subtype", "ambiguous", "rationale",
                    "retry_eligible_expected", "annotator"])
        for r in dev + test:
            w.writerow([r["id"], r["split"], r["repo"], r.get("failed_step") or "", r["outcome_kind"],
                        json.dumps(r["flaky_evidence"]), "|".join(r["heuristic_hint"]), r["primary_error"],
                        r["excerpt"][:2500], "", "", "", "", "", ""])

    # coverage report
    lines = []
    lines.append(f"input records: {total_in}  usable(log ok): {len(usable)}  dropped(no log/excerpt): {dropped_nolog}")
    lines.append(f"unique signatures (usable): {len({r['signature'] for r in usable})}")
    lines.append(f"after cap of {args.max_per_signature}/signature: {len(capped)}  -> dev {len(dev)} / test {len(test)}")
    for title, key in (("by repo", lambda r: r["repo"]), ("by outcome kind", lambda r: r["outcome_kind"]),
                       ("by split reason", lambda r: r["split_reason"])):
        lines.append(f"\n{title}:")
        for k, n in Counter(key(r) for r in capped).most_common():
            lines.append(f"  {k:60} {n}")
    hint_counts: Counter = Counter()
    for r in capped:
        for h in r["heuristic_hint"]:
            hint_counts[h] += 1
    lines.append("\nweak hints (a record can match several; NOT labels):")
    for k, n in hint_counts.most_common():
        flag = "  <-- below ~25-30 target: add fault-injected samples" if k.endswith("?") and n < 30 else ""
        lines.append(f"  {k:30} {n}{flag}")
    n_multi = sum(1 for r in capped if len([h for h in r["heuristic_hint"] if h.endswith('?')]) > 1)
    lines.append(f"\nrecords matching >1 hint (guideline decisions needed): {n_multi}")
    lines.append(f"records with NO_HINT (manual triage / possible UNKNOWN): {hint_counts['NO_HINT']}")
    report = "\n".join(lines)
    (out / "coverage_report.txt").write_text(report, encoding="utf-8")
    print(report)
    print(f"\nWrote {out/'splits'/'dev.jsonl'}, {out/'splits'/'test.jsonl'}, {out/'annotation_sheet.csv'}")


# --------------------------------------------------------------------------- #
# Offline self-test
# --------------------------------------------------------------------------- #
def cmd_selftest(_args) -> None:
    # --- redaction (fake secrets assembled at runtime so scanners don't flag this file)
    gh = "gh" + "p_" + "A1b2C3d4E5" * 4
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcDEF123_-xyz789"
    sample = "\n".join([
        f"token: {gh}",
        f"AWS_ACCESS_KEY_ID={aws}",
        f"AWS_SECRET_ACCESS_KEY={'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY'}",
        f"Authorization: Bearer {jwt}",
        "git clone https://deploy:" + "s3cr3tPass" + "@github.com/org/repo.git",
        "DB_PASSWORD=hunter2hunter2",
        "contact: dev.person@example.com",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
        "plain line: build failed with 3 errors",
    ])
    red, counts = redact(sample)
    for needle in (gh, aws, jwt, "s3cr3tPass", "hunter2hunter2", "dev.person@example.com", "MIIEabc",
                   "wJalrXUtnFEMI"):
        assert needle not in red, f"leaked: {needle[:12]}"
    assert "build failed with 3 errors" in red
    print("redaction ok:", counts)

    # --- excerpt / primary error (generic exit code -> real error found earlier)
    log = "\n".join([
        "2026-01-05T10:00:00.1234567Z ##[group]Run mvn -B package",
        "2026-01-05T10:00:01.0000000Z [INFO] Scanning for projects...",
        "2026-01-05T10:00:09.0000000Z [ERROR] Failed to execute goal on project api: Could not resolve dependencies "
        "for project com.acme:api:jar:1.4.2: Could not transfer artifact org.x:y:pom:2.3.1 from central",
        "2026-01-05T10:00:09.5000000Z ##[error]Process completed with exit code 1.",
        "2026-01-05T10:00:10.0000000Z Post job cleanup.",
    ])
    info = analyze_log(preprocess(log), 6000)
    assert "Could not resolve dependencies" in info["primary_error"], info["primary_error"]
    assert "##[group]Run mvn" in info["excerpt"]
    print("excerpt ok:", info["primary_error"][:70], "...")

    # --- signature stability across versions / ids / paths
    s1, _ = make_signature("[ERROR] Could not transfer artifact org.x:y:pom:2.3.1 from /home/runner/work/a/b", "Run mvn package")
    s2, _ = make_signature("[ERROR] Could not transfer artifact org.x:y:pom:2.4.0 from /home/runner/work/c/d", "Run mvn package")
    s3, _ = make_signature("[ERROR] Tests run: 12, Failures: 2", "Run mvn package")
    assert s1 == s2 and s1 != s3
    print("signature ok:", s1, s3)

    # --- hints
    h = heuristic_hints("Could not resolve dependencies ... Connection timed out", [])
    assert "BUILD_DEPENDENCY?" in h and "INFRA_FLAKY?" in h  # intentionally ambiguous
    assert heuristic_hints("something odd", []) == ["NO_HINT"]
    print("hints ok:", h)

    # --- per-signature cap is round-robin across repos
    recs = [{"signature": "a", "repo": r, "created_at": f"2026-01-0{i}"} for i, r in
            enumerate(["x", "x", "x", "y", "y", "z"], start=1)]
    kept = cap_per_signature(recs, 3)
    assert {r["repo"] for r in kept} == {"x", "y", "z"}
    print("cap ok")
    print("\nALL SELF-TESTS PASSED")


# --------------------------------------------------------------------------- #
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--repos", nargs="*", help="owner/repo ...")
        sp.add_argument("--repos-file", help="file with one owner/repo per line")
        sp.add_argument("--days", type=int, default=90, help="look-back window (default 90)")
        sp.add_argument("--workflow", action="append", default=[],
                        help="only workflows whose name contains this text (repeatable)")
        sp.add_argument("--include-recovered", action="store_true",
                        help="also collect earlier failed attempts of runs that passed after a re-run "
                             "(best source of flaky ground truth)")
        sp.add_argument("--api-url", default=API_DEFAULT, help="GitHub API base (for GHES)")
        sp.add_argument("--out", default="data")

    a = sub.add_parser("inventory", help="count failures per repo/workflow/step")
    common(a)
    a.add_argument("--no-jobs", action="store_true", help="skip per-run job lookups (fast, run-level counts only)")
    a.set_defaults(fn=cmd_inventory)

    c = sub.add_parser("collect", help="download + redact + excerpt failed-job logs")
    common(c)
    c.add_argument("--max-records", type=int, default=0, help="stop after N new records (use for a trial run)")
    c.add_argument("--max-excerpt-chars", type=int, default=6000)
    c.add_argument("--max-log-mb", type=int, default=25, help="per-job log cap; the tail is kept")
    c.add_argument("--save-logs", metavar="DIR", help="also store REDACTED full logs (gzip) in DIR")
    c.add_argument("--aggressive", action="store_true", help="also mask long mixed alphanumeric tokens")
    c.set_defaults(fn=cmd_collect)

    s = sub.add_parser("split", help="cap duplicates, split dev/test, write annotation sheet")
    s.add_argument("--in", dest="input", required=True, help="raw_candidates.jsonl")
    s.add_argument("--out", default="data")
    s.add_argument("--max-per-signature", type=int, default=4)
    s.add_argument("--test-frac", type=float, default=0.3)
    s.add_argument("--holdout-repos", help="comma-separated repos used ONLY for test (unseen-repo generalisation)")
    s.add_argument("--seed", default="devrer-golden-v1")
    s.set_defaults(fn=cmd_split)

    t = sub.add_parser("selftest", help="offline checks")
    t.set_defaults(fn=cmd_selftest)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
