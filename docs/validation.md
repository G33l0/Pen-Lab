# Validation & false-positive architecture

The central promise: **an interesting-looking response is never confused with a
confirmed vulnerability.** This is enforced structurally, not by convention.

## Building blocks

- **`HttpExchange`** — a captured request/response with status, headers, body,
  timing, content type, redirects, and a body hash.
- **`Signal`** — one piece of reasoning, typed as `detection`, `validation`,
  `negative`, or `false_positive`, each `observed` true/false with detail.
- **`DifferentialAnalyzer`** — compares two exchanges across many independent
  dimensions (status, headers, cookies, size, body hash, **normalized** text
  similarity, content type, redirects, timing). Text similarity is measured on a
  body where volatile tokens (UUIDs, long hex, timestamps, CSRF-looking values,
  digits) are masked, so dynamic content does not read as a difference.
- **`ValidationResult`** — binds a `FindingStatus` + `Confidence` to the signals
  and metrics that justify it.

## The evidentiary bar

Detectors may raise a finding to POTENTIAL/SUSPECTED on heuristics, but only
**corroborated, deterministic** evidence reaches VALIDATED/CONFIRMED. A single
weak indicator (a 200, a 500, a length change, an SQL-looking string) can never
be CONFIRMED.

Every detector also consults shared **false-positive heuristics** that recognise
benign causes — WAF block pages, rate limiting (429), authentication redirects —
and returns a non-actionable verdict when they are present.

## Detector logic

- **Reflected XSS** (`reflected_xss`): (1) unique marker reflected, (2) reflected
  **un-encoded in an executable context**, (3) **runtime confirmation** in a
  controlled browser. Only runtime confirmation yields CONFIRMED; reflection
  alone is at most SUSPECTED; an HTML-encoded reflection is evidence *against*.
- **Differential SQLi** (`differential_sqli`): requires a coherent differential —
  boolean (TRUE≈baseline while FALSE diverges beyond measured noise), error-based
  (a DB error signature absent from baseline), or time-based (a reproducible
  injected delay far above baseline jitter). The endpoint's intrinsic noise is
  measured first; a noisy endpoint yields INCONCLUSIVE. One signal → VALIDATED,
  two independent signals → CONFIRMED. A lone status/size change is explicitly
  marked insufficient.
- **Open redirect** (`open_redirect`): deterministic — the effective redirect
  target host equals a controlled external host → CONFIRMED; same-origin → not a
  finding.

## The regression suite

`tests/test_false_positive_regression.py` feeds benign-but-tricky responses
(normal page, generic 500, 429 rate limit, WAF block, auth/login redirect,
custom error page, dynamic content, length-only change, encoded reflection,
same-origin redirect) and asserts no detector returns an actionable verdict.
Positive counterparts live in `tests/test_validation.py`, and end-to-end tests
in `tests/test_execution.py` run the detectors against a local intentionally-
vulnerable mock HTTP target.
