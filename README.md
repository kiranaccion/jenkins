# DevRER Golden-Set Collection: Team Handover Guide

**Script:** `golden_set_collector.py`
**Purpose:** Collect real CI failures from our GitHub Actions repos, redact them, and prepare a dataset that humans label. The labelled set is used to evaluate the DevRER failure classifier (Nova 2 Lite vs alternatives) and the RCA quality.

> **Status note:** The script passed its offline self-test and an end-to-end test against a simulated GitHub client. It has **not yet been run against the live GitHub API**. Always do the small trial run (Step 3) and inspect the output before the full run.

---

## 1. What you are producing

A reviewed, redacted file of about **200 failure records** (more is better) across our 10-15 service repos, with a human-assigned label for each.

Labels (one per record):

| Label | Meaning (short) |
|---|---|
| `BUILD_DEPENDENCY` | Compile, dependency resolution, image build/pull failures |
| `CODE_QUALITY` | SonarQube quality gate / static-analysis failures |
| `VULNERABILITY` | Snyk / CVE policy findings |
| `TEST_FAILURE` | Deterministic unit/integration test failures |
| `INFRA_FLAKY` | Transient runner/network/service problems, intermittent failures |
| `UNKNOWN` | Anything else: workflow YAML errors, permissions/auth, missing secrets, ECR push errors, timeouts, disk full, etc. |

Targets:
- At least **25-30 records per label**, including `UNKNOWN`
- At most **3-5 records per distinct failure signature** (the script enforces the cap)
- Synthetic (fault-injected) records should be **no more than about one third** of the set and are always tagged `source: synthetic`
- Reserve **1-2 whole repos as hold-out** (test only) to measure how well we generalise to an unseen repo

---

## 2. Prerequisites

- Python 3.9+ (tested on 3.12) and `pip install requests`
- A **read-only** GitHub token for the repos in scope:
  - Fine-grained personal access token or GitHub App installation token
  - Repository permissions: **Actions: Read**, **Metadata: Read**
  - Limit it to the selected repos only. Do not use a broad or admin token.
- Set it in your shell: `export GITHUB_TOKEN=<token>` (the script also accepts `GH_TOKEN`, or falls back to `gh auth token` if the GitHub CLI is installed)
- A `repos.txt` file, one `owner/repo` per line (lines starting with `#` are ignored):

```
# repos.txt
acme/payments-service
acme/orders-service
acme/auth-service
```

- For GitHub Enterprise Server, add `--api-url https://<host>/api/v3` to every command.

---

## 3. Step-by-step

All commands run from the folder containing the script. `--out` defaults to `data/`.

### Step 0: Self-test (10 seconds, no network)

```bash
python golden_set_collector.py selftest
```
Expect `ALL SELF-TESTS PASSED`.

### Step 1: Inventory (see what exists before downloading anything)

```bash
python golden_set_collector.py inventory --repos-file repos.txt --days 90 --include-recovered
```

Outputs `data/inventory.csv` (counts by repo, workflow, failed step, kind) and prints a per-repo summary.

Use it to:
- Decide which workflows matter (add `--workflow "CI"` to restrict to workflows whose name contains that text; the flag can be repeated)
- Spot repos with very few failures
- **Note the date:** GitHub keeps logs for about 90 days by default, so older failures may already be gone.

Add `--no-jobs` for a faster run-level-only count (skips per-run job lookups).

### Step 2: Small trial collection

```bash
python golden_set_collector.py collect --repos-file repos.txt --days 90 \
    --include-recovered --max-records 20
```

Open `data/raw_candidates.jsonl` and check a few records:
- `excerpt` shows the real error and is readable
- `primary_error` is the actual error line, not just "Process completed with exit code 1"
- No secrets, tokens, passwords or emails remain in `excerpt` (see Section 5)
- `log_status` is mostly `ok`

If anything looks wrong, stop and tell the owner (Section 8) before running the full collection.

### Step 3: Full collection

```bash
python golden_set_collector.py collect --repos-file repos.txt --days 90 \
    --include-recovered --save-logs data/logs
```

- Safe to re-run: records already collected are skipped, so you can resume after an interruption.
- `--save-logs data/logs` also stores the **redacted** full logs (gzip) for later reference. Skip it if storage or sensitivity is a concern.
- `--aggressive` additionally masks long random-looking tokens. Use it if the trial showed leakage; it may also mask some legitimate hashes.
- Rate limits are handled automatically (the script sleeps and continues).

### Step 4: Split and prepare the annotation sheet

```bash
python golden_set_collector.py split --in data/raw_candidates.jsonl \
    --holdout-repos acme/orders-service,acme/auth-service
```

Optional flags: `--max-per-signature 4` (default 4), `--test-frac 0.3` (default 0.3).

Outputs:

| File | Contents |
|---|---|
| `data/splits/dev.jsonl` | Dev records (used to tune prompts, choose few-shot examples) |
| `data/splits/test.jsonl` | Locked test records. **Nobody tunes against these.** |
| `data/annotation_sheet.csv` | Sheet for reviewers: excerpt, hints, blank label columns |
| `data/coverage_report.txt` | Counts by repo, kind and hint, with gaps flagged |

Read `coverage_report.txt` first. Any hint category under about 30 records is flagged: fill the gap with fault injection (Section 6).

---

## 4. How the data is organised

Each record in the JSONL files includes:

- **Identity:** `id`, `repo`, `workflow`, `run_id`, `run_attempt`, `job_name`, `failed_step`, `run_url`, `branch`, `head_sha`
- **Evidence:** `primary_error`, `error_lines`, `excerpt` (redacted, error-centred), `log_status`
- **Dedup and grouping:** `signature` (stable across repos and runs), `signature_text`
- **Flaky evidence:**
  - `outcome_kind = recovered_after_rerun`: an earlier attempt failed, then the same run passed after a re-run. This is strong evidence of a transient failure.
  - `flaky_evidence.passed_later_on_same_sha`: a later run of the same workflow on the same commit passed (weaker signal)
- **`heuristic_hint`:** keyword guesses such as `BUILD_DEPENDENCY?`, `INFRA_FLAKY?`, `NO_HINT`. **These are not labels.** They exist only to count coverage and to find ambiguous cases. A record matching two hints (for example a timeout while downloading dependencies) needs a decision from the labelling guide.
- **Human fields (empty at first):** `gold_label`, `subtype`, `ambiguous`, `rationale`, `annotators`, `retry_eligible_expected`, `reference_root_cause`

---

## 5. Security and data handling (important)

1. **Redaction is regex-based best effort, not a guarantee.** It masks GitHub, AWS, Slack and Sonar tokens, JWTs, private keys, URL credentials, `password=`/`token=`-style pairs, auth headers and emails. It does **not** mask hostnames, internal URLs, project or customer names.
2. **Spot-check before sharing.** Skim at least 20 records, especially from repos that handle credentials or customer data, and search the files for `password`, `secret`, `key`, `token`, `@`.
3. **Store outputs in a restricted location** (access limited to the team). Do **not** commit `raw_candidates.jsonl`, `logs/` or the annotation sheet to shared or public repositories.
4. If you find a leaked secret in any output, delete the affected files, **rotate the secret**, and tell the owner immediately.
5. Confirm with the owner that we have permission to use logs from each repo (some may belong to client projects).
6. The script is **read-only**. It only issues GET requests and never changes anything in GitHub.

---

## 6. Filling gaps with fault injection (synthetic failures)

Rare categories (Sonar gate, Snyk, some infra failures, `UNKNOWN`) often lack history. In a **sandbox repo or fork, never `main` of a real service**, create `workflow_dispatch` pipelines that mirror our stack and break them on purpose:

| Class | How to induce it |
|---|---|
| BUILD_DEPENDENCY | Pin a non-existent dependency version; break the Dockerfile |
| CODE_QUALITY | Tighten the Sonar quality gate, or add code that violates it |
| VULNERABILITY | Add a known-vulnerable dependency so Snyk flags it |
| TEST_FAILURE | Add a deterministic failing test |
| INFRA_FLAKY | A step calling an unreachable host; a test that fails randomly |
| UNKNOWN | Invalid workflow YAML; missing secret; ECR push with bad permissions; out-of-disk; timeout |

Add the sandbox repo to a **separate** `repos_synthetic.txt`, collect into a separate folder (`--out data_synthetic`), and set `"source": "synthetic"` on those records before merging. Keep synthetic records to about one third of the final set, and report metrics for real and synthetic separately.

---

## 7. Labelling (after the split)

1. Use `data/annotation_sheet.csv`. Fill `gold_label`, `ambiguous` (yes/no), a one-line `rationale`, and your name in `annotator`. For records whose failure is plausibly transient, fill `retry_eligible_expected` (yes/no).
2. **Follow the labelling guide**, which the owner will provide separately. It decides the ambiguous cases (dependency-download timeouts, scanner auth failures, ECR push errors, flaky vs. real test failures). Do not invent your own rules; raise questions instead.
3. **Double-label about 20%** of records with a second reviewer and note where you disagree. Low agreement means the guide needs fixing, not the reviewers.
4. For about **40-50** incidents, also write `reference_root_cause` (one or two sentences). Useful sources: the next green run on the same branch and the commit diff in between.
5. Do not look at the model's predictions while labelling.
6. Keep the **test split locked**: do not use test records as few-shot examples or for tuning.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `No token found` | `GITHUB_TOKEN` not set in this shell |
| `401` / `403` on a repo | Token lacks **Actions: Read** or does not include that repo |
| `404` on a repo | Wrong `owner/repo`, or token has no access |
| Many records with `log_status: expired` | Logs older than the retention window; these are dropped by `split`. Collect sooner or reduce `--days`. |
| `log_status: missing` | Log not available for that job (cancelled, deleted); also dropped by `split` |
| "[rate limit] sleeping ..." | Normal; the script waits and continues |
| Warning about `>=1000 runs` in a window | A very busy repo; some runs may be missed. Tell the owner. |
| Zero failures found | Wrong `--days`/`--workflow` filter, or the repo is healthy. Check `inventory.csv`. |
| `primary_error` just says "exit code 1" | Log had no recognisable error text before the failure; label from the excerpt and flag it |
| Interrupted run | Re-run the same `collect` command; it resumes without duplicates |

---

## 9. Hand-back checklist

- [ ] `selftest` passed and a 20-record trial was reviewed
- [ ] `inventory.csv` and `coverage_report.txt` shared with the owner
- [ ] At least 25-30 labelled records per label (including `UNKNOWN`), real and synthetic tracked separately
- [ ] 1-2 hold-out repos used; test split untouched during tuning
- [ ] About 20% double-labelled, with disagreements noted
- [ ] `reference_root_cause` written for 40-50 incidents
- [ ] Spot-check for leaked secrets done; outputs stored in the restricted location
- [ ] Confirmation of log-usage permission for each repo

**Questions or issues:** [owner name / contact: to be filled in]
