# GPT-assisted bounded URL review

`ai_review.py` is a separate, optional companion for Passive Scan v8.0.1. The
existing 20-worker reconnaissance workflow remains unchanged. Run this tool
only on targets where program rules explicitly allow the selected traffic.

## What it actually does

1. Reads exact URLs from `reports/recon_history.db` (`master_urls`), a text
   file, or the `urls` array in a JSON config. The DB contains historical URLs;
   these are candidates, **not proof that they still work**. Prioritizes
   recognizable API and search paths and samples one URL per route pattern.
2. Uses a hard cap on URL count, an exact host allowlist, explicit live path
   prefixes, and path exclusions.
3. In live mode, the global planner sees the selected URL assets, prior
   observed facts, manual-review candidates and progress. It chooses one
   available URL/check pair; the bounded worker executes it, records the
   response, and the planner decides again. When the exact URL has a Worker
   capability, the model can construct a short sequence of approved query or
   form values and adapt its next request to observations. The executor checks
   each proposed step against the capability and request policy.
4. Saves JSON Lines containing status, a redacted response preview and body
   hash. An observed reflected marker or cross-account exposure of a marker in
   your **own test object** is a `manual_review` candidate, never an
   automatically submitted report.

The default checks are exact-URL anonymous/own-test-account GETs and a
harmless unique reflection marker. Explicitly configured checks can compare
owned download files across identities, test whether a fixed XSS canary
executes when a captured HTML response is rendered in isolated Chromium,
read back a harmless text upload from an exact URL, and compare repeated
read-only SQL true/false conditions against an owned marker. These provide
stronger observations for specific flows; no universal vulnerability proof
is possible from URLs alone. The system does not infer POST schemas, execute
arbitrary scripts, extract database data, or test SSRF and financial actions.

## Adaptive test selection from the URL list

Each candidate report includes `test_candidates`: authorization, download,
reflection, browser canary, SQL comparison, and upload hypotheses inferred from path and query-key
features. The report distinguishes a ready test definition from one needing
additional configuration. **A URL label is a lead, not evidence.** The model
sees the available actions and actual observations, then chooses one action
at a time; code independently checks its choice. The single HTML report shows
the hypotheses alongside plans and observations. Offline mode lists candidate
tests without contacting the target or the model.

`enabled_test_kinds` restricts the selectable families. If omitted, the
original GET/account/reflection behavior is retained. An empty list permits
only anonymous baseline GETs. For example:

```json
{
  "enabled_test_kinds": ["access_control", "download_access", "reflection",
                         "xss_browser", "sql_error", "sql_boolean", "upload", "upload_verify"],
  "active_tests": {
    "https://example.test/search?q=shoes": {
      "xss_browser": {"parameter": "q"}
    },
    "https://example.test/items?id=123": {
      "sql_boolean": {"parameter": "id"}
    },
    "https://example.test/upload": {
      "upload": {"field": "file", "identity": "a",
                 "verify_url": "https://example.test/files/owned-test.txt",
                 "verify_identity": "b"}
    }
  },
  "expectations": {
    "https://example.test/items?id=123": {"sql_marker": "OWNED_TEST_MARKER"},
    "https://example.test/upload": {"uploaded_file_must_be_private": true}
  }
}
```

Merge these keys into the normal config along with exact `allowed_hosts`,
`live_path_prefixes`, and request limits. A SQL probe requires a healthy
anonymous baseline, then appends a single apostrophe to a named, existing
query parameter. It records the HTTP response for human comparison; no
SQL injection finding is generated. `sql_boolean` requires one numeric
parameter, a healthy anonymous baseline containing `sql_marker`, and
four remaining requests. It compares fixed true/false conditions twice.
A stable marker difference becomes `manual_review`, not a confirmed SQLi.
The upload action sends one generated
`.txt` file with a harmless marker to the exact configured URL and field.
Only the configured test identity can be used, with a token supplied through
the existing credential environment mapping. If `upload_verify` is enabled,
it fetches only `verify_url` and checks the generated marker. A different
identity reading a file configured as private becomes `manual_review`.
Accepted uploads alone are not reported. A different form schema or upload
destination needs an explicit test definition.

For a download URL, set the existing `expectations` fields `owner`,
`private_marker`, and `other_account_must_be_denied` for a file you own.
The owner baseline and the other account's response must both contain
the marker for a `download_access` review candidate. A truncated response
cannot establish a negative result. The `xss_browser` action requires a
reflected marker in an HTML response first, then submits a fixed canary
through the configured existing search parameter. Chromium renders only
the captured response at its origin; other browser HTTP and WebSocket
requests are blocked. Execution is a manual-review candidate. A missing
execution signal does not prove the absence of XSS.

Global planning is on by default for a live run. It sees a compact asset
inventory of the URLs selected from reconnaissance, the last 100 observed
facts with per-URL evidence IDs, current manual-review candidates, which
checks have been attempted, and remaining available actions. It does not
have the entire reconnaissance database or a complete authenticated request
history. Every response updates the shared situation before the next model
decision. The model can stop; untouched URLs remain `not_selected`, never
`safe`. `max_planning_steps` defaults to 20 and cannot exceed the HTTP
request budget. To compare with the previous per-URL loop, explicitly set
`"adaptive_planning": false` in a local config.

For the fixed checks, model output cannot change the configured URL,
parameter, field, method, headers, or payload. The optional Worker capability
below allows the model to generate values for explicitly named fields. A
configured POST action runs only when its test family and exact URL are
enabled. Apply it to authorized disposable test data. The global request
budget, host/path policy, one-second minimum interval, no-redirect behavior,
and 429/5xx stop still apply.

## Model-generated Worker steps

Enable `investigate` and grant a narrow capability per exact URL. The model
proposes one request at a time, reads redacted response previews, and can
form a different follow-up request. This example permits three GET steps on
the named search parameter:

```json
{
  "enabled_test_kinds": ["investigate"],
  "worker_capabilities": {
    "https://example.test/search?q=sample": {
      "methods": ["GET"],
      "query_keys": ["q"],
      "identities": ["anonymous"],
      "max_steps": 3
    }
  }
}
```

For an authorized disposable form, configure its exact URL with
`"methods": ["POST"]`, `"form_fields": ["query"]`, and an approved
`identities` entry. The Worker sends URL-encoded form data and can use at
most five fields and five steps. It cannot select a different host/path,
add arbitrary fields or headers, use another HTTP method, run shell tools,
or submit external URLs or destructive SQL strings as values. Values have
an 80-character limit. Configure POST only for forms whose side effects
are acceptable in the test environment.

The report records the proposed steps and actual HTTP observations. The
Worker may link observed evidence IDs into `worker_leads`, which are
inferences for manual review, not confirmed findings. The Planner can use
these leads in its next decision. This capability requires global adaptive
planning (`adaptive_planning` defaults to `true`) and a live run. Offline
mode still lists it as a candidate without executing requests.

This version uses GPT through the OpenAI Responses API. MCP is optional: the
same bounded HTTP operations could later be exposed as MCP tools.

## First run: offline, no target HTTP or GPT calls

```bash
cp ai_review.example.json ai_review.config.json
# Edit allowed_hosts, URLs, request limits and, if applicable, expectations.
python3 ai_review.py --config ai_review.config.json --output review_plan.jsonl
```

To use an exported v8.0.1 SQLite report or a newline-delimited URL file:

```bash
python3 ai_review.py --config ai_review.config.json \
  --db reports/recon_history.db --output review_plan.jsonl
python3 ai_review.py --config ai_review.config.json \
  --urls-file candidate_urls.txt --output review_plan.jsonl
```

The Actions report artifact is the password-protected
`passive-recon-master-report-secured` archive. Download it, decrypt the inner
ZIP with your Actions password, and provide its `recon_history.db` locally.
Never store decrypted reports, access tokens or response output in a public
repository. A URL may itself contain sensitive query values; remove or redact
them before uploading a configuration or sharing a result.

## Live mode: explicit authorization required

### Local ChatGPT Plus/Pro sign-in (no separate API key)

Use this only on your own computer with an eligible ChatGPT account. Install
`openai` and `cryptography`, then authorize this app once in the browser that
runs on the same computer as the CLI. Approve ChatGPT plan usage if prompted.

```bash
python3 -m pip install openai cryptography
python3 chatgpt_auth.py login
python3 chatgpt_auth.py models
python3 ai_review.py --auth chatgpt --live --config ai_review.config.json \
  --urls-file candidate_urls.txt --output review_results.jsonl
```

The first listed model is selected by default. To choose another, set
`chatgpt_model` in the local JSON config to a slug printed by `models`.
The credentials and stable host ID live in owner-only files in
`~/.config/passive-scan-review/`. Keep this directory and the JSONL output
private. Refresh tokens are rotated automatically. The optional GitHub Actions review can also use the protected ChatGPT session
when you explicitly select `chatgpt` authentication.
ChatGPT plan usage has its own limits and is not an unlimited six-hour batch
quota. The application never obtains your ChatGPT conversation history.

To exercise real GPT decisions on the controlled fake site, after login run:

```bash
python3 tests/lab_demo.py --chatgpt --output lab_gpt_results.jsonl
```

This lab starts a local server, gives the planner only bounded GET choices,
and writes each observed result. Unlike the fixed lab planner, GPT can choose
`stop` or other permitted actions, so the number of findings can vary. The
default lab run without `--chatgpt` remains deterministic and offline.

### API-key mode

Install optional API dependency and set your OpenAI API key locally. If using
two authorized test accounts, map environment variables in the JSON config;
tokens are read on the test runner and are never included in model input.

```bash
python3 -m pip install openai
export OPENAI_API_KEY='your_api_key'
export REVIEW_ACCOUNT_A_TOKEN='your_owned_test_account_a_token'
export REVIEW_ACCOUNT_B_TOKEN='your_owned_test_account_b_token'
python3 ai_review.py --config ai_review.config.json \
  --db reports/recon_history.db --output review_results.jsonl --live
```

`--live` requires exact `allowed_hosts` and nonempty `live_path_prefixes`;
review these prefixes before every run. It does not follow redirects or use
environment HTTP proxies, rejects private/non-global DNS results, sends GETs
only, times out after five seconds, caps body reads at 16 KiB, and stops after
429 or 5xx. A private local lab additionally needs `--allow-private-lab`.
The built-in minimum pause is one second per host; **set a lower request
budget according to the actual program rules**. DNS checks cannot eliminate
all network and rebinding risks; use a restricted network runner or egress
proxy for production use. The model receives redacted response previews and
may still receive site text; do not run on sensitive personal data without an
appropriate data-handling arrangement.

## How to interpret results

- `dry_run`: candidate categorized with no model call and no target request.
- `manual_review`: a specific observation worth human verification; the
  reflection result is **not** an XSS finding.
- `halted_on_server_signal`: stopped on 429 or 5xx; do not automatically retry.
- `model_unavailable` / `request_error`: no verified conclusion.

Each new JSONL row also separates the investigation stages:

- `hypotheses`: a pre-request question for a supported reflection check or a
  configured, owned test-object access comparison. `not_tested` means no useful
  comparison has been made; `no_signal_observed` does not prove safety;
  `needs_manual_review` means an observation met the candidate rule.
- `plans`: the model's bounded next-action choice and its testable question,
  always marked `inferred`. These are not response evidence.
- `facts`: actual HTTP observations marked `observed`, with stable per-candidate
  IDs (`obs-1`, `obs-2`, …), HTTP status and response SHA-256. The observation
  also retains the redacted preview in the encrypted result.
- `findings`: still only `manual_review` candidates. Each entry now lists the
  observation IDs that support it; an access comparison needs both the owner
  baseline and the other identity's response. A response code alone never
  establishes a vulnerability.

The protected HTML report shows these stages and evidence links. Older
encrypted JSONL artifacts can still be exported; missing stage fields appear
as empty sections rather than fabricated evidence. The model's instructions
ask for testable questions, while response-derived facts and finding links are
constructed by code from actual observations.

For cross-account checks, set an expectation only for a **test object that
you own**, including an innocuous marker known in advance and a rule that
other-account access should be denied. A second 200 response alone is not
reported as an access-control vulnerability.

The full reconnaissance workflow offers an opt-in `plus_review` switch. When
selected on `main` by the repository owner, it runs the bounded live review
after the secured report is uploaded. No production target run is implied by
the local lab.

## Optional GitHub Actions review

Set `AI_REVIEW_CONFIG_JSON` to an edited JSON policy with exact
`allowed_hosts` and nonempty `live_path_prefixes`. Set
`ACTIONS_CRYPTO_PASSWORD` to the password protecting the recon report. Add
own test-account token secrets only if their checks are explicitly approved.
For API-key live mode, also set `OPENAI_API_KEY`.

The manual **Bounded GPT review of a passive recon run** workflow takes a
completed recon run ID, defaults to offline planning, and offers `api-key` or
`chatgpt` authentication. `chatgpt` live review uses the encrypted session
checkpoint established by the separate Plus lab. It restores the latest
checkpoint, selects permitted model actions, then saves a newly encrypted
checkpoint even if review fails after restoration. Both workflows serialize
access to the rotating token. The results are encrypted in the
`bounded-ai-review-secured` artifact.

### Read a review result on a phone or computer

Open the completed review run in GitHub Actions and read the Korean **한정 범위
검토 요약**. It shows each page's number, state, category, HTTP actions
and manual-review kind. This summary deliberately omits target URLs, query
values, response bodies and finding reasons. It does not identify a confirmed
vulnerability.

For full evidence, download the `bounded-ai-review-secured` artifact. The
downloaded outer ZIP contains `bounded-ai-review-readable.zip` (AES-256) and
the original `ai_review_results.jsonl.gpg`. Open the inner ZIP with an
AES-encrypted-ZIP-capable archive app using the `ACTIONS_CRYPTO_PASSWORD`
value. Extract the inner ZIP to a private location and open the single
`review_report.html` in a browser. Its Korean dashboard and per-page detail
views are all in this one file; links move between them without a network
connection. The
`ai_review_results.jsonl` file is included for tooling. The archive and
extracted files contain target details and response previews. Interface labels
and known checks are shown in Korean; original model reasons and recorded
evidence remain available in expandable sections without automatic translation.
You can still decrypt the GPG file with GnuPG on a computer. Never use the
GitHub account password or ChatGPT password for either archive. Existing runs
created before this report change only contain the GPG file. To export one
without another target request or model call, open Actions → **Export an
existing bounded review as a readable report** → **Run workflow** on `main`
and enter that completed bounded review run's ID as `review_run_id`. Its
summary contains the candidate table, and its `bounded-ai-review-readable`
artifact contains the AES-256 ZIP described above. The original GPG artifact
must still be available, and both result artifact types are retained for 7 days.

Alternatively, choose `full` and enable `plus_review` when manually running
**Automated Parallel Passive Reconnaissance** on `main`. Its report job must
succeed before the Plus review starts. The switch is off by default and the
workflow's schedule is currently disabled. Ensure the target policy and the
recon workflow's own target secrets are configured before running it. The
review reads historical URLs from the report, filters them to the exact hosts
and approved path prefixes, and makes only its bounded GET requests. It does
not commit scan data or credentials.

## Repeatable local HTTP lab

To check the real request/response and report path without touching an
external site, run `python3 tests/lab_demo.py --output lab_review_results.jsonl`
in an environment that allows binding `127.0.0.1:18080`. The script starts
a temporary local site, creates a tiny SQLite URL report, issues three GETs
through the normal reviewer, checks the resulting manual-review candidates,
and shuts the site down. It models an account B reading account A's own test
order and a search term echoed in JSON. The latter is **not** XSS.

The lab uses a fixed decision planner in place of the OpenAI API, so it
tests the HTTP, policy and result path but does not validate GPT connectivity
or model decisions. No GitHub Actions secrets are needed for this local test.

GitHub Actions also runs `tests/lab_chatgpt_mock.py`, which supplies streamed
model-style decisions to the actual `ChatGPTPlanner` and sends bounded GETs to
the local lab. It verifies the resulting findings without an account or API
key. It cannot prove interactive ChatGPT login, account permission, live model
availability, or model behavior: those require a separate local sign-in test.

## Renewable real ChatGPT Plus test in GitHub Actions

For a manual run against the same **local fake site** on a GitHub-hosted runner:

1. On your own computer, install the optional Python dependencies and sign in
   with `python3 chatgpt_auth.py login`. Install and authenticate GitHub CLI
   (`gh auth login`) if needed.
2. Run `python3 chatgpt_auth.py ci-bootstrap` on that computer. It registers
   the initial protected session and a random encryption key as separate
   Actions Secrets. Both are sent to `gh secret set` over standard input.
3. Open Actions → **ChatGPT Plus local lab (manual)** → **Run workflow**
   on `main`. It lists available models, runs real streamed model decisions
   against `127.0.0.1:18080` within that runner, and checks that the review
   completed. The model can choose `stop`, so a specific finding is not required.
4. After the first successful run, remove the initial bootstrap secret with
   `gh secret delete CHATGPT_CI_BOOTSTRAP --repo ohjun1998/passive-scan_v8.0.1_pub`.
   **Keep `CHATGPT_CI_KEY`** while you want to reuse the encrypted checkpoint.

Each run restores the latest AES-GCM-encrypted session artifact, refreshes the
access token as needed, then uploads a fresh encrypted checkpoint. The
encryption key remains in Actions Secrets, and each artifact is retained for
30 days. Runs are serialized to avoid racing the rotating refresh token.
PR jobs do not run a live Plus review; the opt-in full reconnaissance run
can pass the protected credentials to its review job.
The old `ci-secret` command remains an alias for `ci-bootstrap`.

If a run does not happen for more than 30 days, the refresh token or artifact
may expire. If ChatGPT access is revoked, the encryption key is lost, or a run
stops between token rotation and checkpoint upload, sign in and bootstrap
again, then choose `reset_session` on the manual workflow. This test still
only scans the fake local site. GitHub-hosted runners do not preserve local
files between jobs; the encrypted artifact is the persistent state.

## Interactive local web lab

`python3 tests/lab_web_flow.py` starts an ephemeral HTTP site on
`127.0.0.1` with synthetic Alice/Bob accounts. It exercises login, a one-time
password reset, post creation, comments and HTML escaping, then writes five
GET URLs to a temporary `recon_history.db` and passes them through the real
bounded reviewer. The default fixed planner checks all five HTTP candidates.
No account or external target is needed.

The manual **ChatGPT Plus local lab** workflow can additionally run this site
with the restored Plus session by leaving `interactive_site` enabled. The site
is reachable only inside that one runner. Its account data and SQLite report
are temporary; it is not a public domain and does not run the 20-worker
reconnaissance workflow. A public end-to-end scan needs a separately owned
public hostname and hosting arrangement.
