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
3. In live mode, asks GPT which of a small number of allowed checks to do next.
   It returns the bounded, redacted HTTP response observation to GPT and may
   choose a follow-up check. Model output cannot select arbitrary URLs, HTTP
   methods, headers, account tokens, or payloads.
4. Saves JSON Lines containing status, a redacted response preview and body
   hash. An observed reflected marker or cross-account exposure of a marker in
   your **own test object** is a `manual_review` candidate, never an
   automatically submitted report.

The implemented checks are exact-URL anonymous/own-test-account GETs and a
harmless unique reflection marker in an existing search query parameter. It
does **not** prove XSS from reflection, infer an API's POST body from a URL,
or test SQL injection, upload flows, SSRF, financial actions, and other
state-changing features. Adding those requires specific test accounts,
expected behavior, safety constraints and independent validators.

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
private. Refresh tokens are rotated automatically. This login is only for
local use; the separate GitHub Actions workflow continues to use its API key.
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

For cross-account checks, set an expectation only for a **test object that
you own**, including an innocuous marker known in advance and a rule that
other-account access should be denied. A second 200 response alone is not
reported as an access-control vulnerability.

Existing v8.0.1 scan speed is unaffected: this script is intentionally not
called from `passive_recon.yml`. GPT/API availability and an actual production
bug-bounty run have not been verified in this deliverable.

## Optional GitHub Actions run

The separate `Bounded GPT review of a passive recon run` workflow accepts the
completed recon run ID and has `live=false` by default. Store the contents of
your edited JSON config in the `AI_REVIEW_CONFIG_JSON` Actions secret; add
`OPENAI_API_KEY`, `ACTIONS_CRYPTO_PASSWORD`, and optional account token secrets
only where needed. Run it from Actions after the recon workflow completes. It
downloads the **specified** report, reads the SQLite URL list, and uploads
encrypted review results as `bounded-ai-review-secured`. It never commits
scan data or credentials to the repository. The optional live toggle requires
the exact hosts and `live_path_prefixes` already configured in the secret.

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

## One-time real ChatGPT Plus test in GitHub Actions

For a manual run against the same **local fake site** on a GitHub-hosted runner:

1. On your own computer, install the optional Python dependencies and sign in
   with `python3 chatgpt_auth.py login`. Install and authenticate GitHub CLI
   (`gh auth login`) if needed.
2. Run `python3 chatgpt_auth.py ci-secret` on that computer. This passes **only
   the short-lived access token** through standard input to `gh secret set` for
   this repository. The refresh token and local credential file stay local.
3. Immediately open Actions → **ChatGPT Plus local lab (manual)** → **Run workflow**
   on `main`. It lists available models, runs real streamed model decisions
   against `127.0.0.1:18080` within that runner, and checks that the review
   completed. The model can choose `stop`, so a specific finding is not required.
4. Remove the temporary secret afterward with
   `gh secret delete CHATGPT_CI_ACCESS_TOKEN --repo ohjun1998/passive-scan_v8.0.1_pub`.

The access token normally expires after one hour. If the job starts after
expiry, repeat step 2. This manual workflow is restricted to repository owner
dispatches on `main`, runs for at most ten minutes, and never contacts a
production target. No Plus account credentials are configured in ordinary PR
or reconnaissance workflows.
