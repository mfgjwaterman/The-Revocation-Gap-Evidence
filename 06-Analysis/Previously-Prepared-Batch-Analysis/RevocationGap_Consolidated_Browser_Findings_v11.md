# The Revocation Gap — Consolidated Browser Findings (v1.1)

**Status:** Retrospective evidence analysis; not a new laboratory run. **Scope:** Chrome and Microsoft Edge; Firefox excluded. **Evidence:** Original `Evidence-Chrome.zip` and `Evidence-Edge.zip`, plus previously extracted CRL DER/serial and verifier inventories (v0.8–v1.0).

## Research question

How do certificate validation mechanisms, HTTP caching, and revocation distribution infrastructure interact to determine the timeliness, reliability, and enforcement of certificate revocation in modern Windows and browser environments?

## Dataset and method

Thirty parseable NetLogs (13 Chrome; 17 Edge) were independently reopened. Event type IDs were resolved from each file's `constants.logEventTypes`. Events were grouped by `(source.type, source.id)` within each file. The analysis identified target-host `CERT_VERIFIER_JOB` begin/end events, `URL_REQUEST_START_JOB` events for `lab-srv-03.corp.michaelwaterman.nl`, and `URL_REQUEST_DELEGATE_SSL_CERTIFICATE_ERROR` events. A source-dependency graph was built from explicit `source_dependency` fields. The graph was used only as a supporting association; absence of an edge is **not** evidence of independence.

The new output (`RevocationGap_Browser_Navigation_Audit_v11.csv`) contains 30 scenario rows. There are **29 target-host verifier jobs**, **83 target-host URL request starts**, and **7 target-host URL requests with an SSL certificate-error delegate event** (the latter are requests, not necessarily seven separate failures or user-visible interstitials). **21 verifier jobs** have a path to a target URL request in the available dependency graph. Importantly, **none of the six key revocation/HTTP-fresh-expiry error scenarios** has such a graph path, despite their independently recorded verifier and request-level errors. Do not claim an exact one-to-one verifier-to-navigation dependency for those cases.

## Observations, interpretations and limits

| Controlled scenario | Verifier observation | Additional navigation observation | Supported interpretation |
|---|---|---|---|
| Chrome DisableCache NewCRL | Completed without recorded `net_error` | Target URL request(s) present | No verifier error recorded for this run; not proof of fresh CRL retrieval by itself |
| Chrome DisableCache Revoke | `net_error=-206` | Target request has SSL certificate-error delegate event | Certificate verifier reports revocation; a target URL request also encounters a certificate-error path |
| Chrome DisableCache Revoke Retest | `-206` | Target request has certificate-error event | Replicated verifier outcome |
| Chrome DisableCache Revoke UniqueURL | `-206` | Target request has certificate-error event | Replicated verifier outcome with distinct URL condition |
| Edge Revoke Baseline | Completed without recorded `net_error` | No target certificate-error delegate event detected | No recorded verifier error in baseline |
| Edge Revoke AfterClear | `-206` | Two target requests have certificate-error delegate events | Verifier detects revocation after clear; multiple request-level events are not independent validation trials |
| Chrome ExpiredCRL HttpFresh | `-205` | Target request has certificate-error delegate event | Verifier reports inability to check revocation despite the experiment's HTTP-fresh condition |
| Edge ExpiredCRL HttpFresh | `-205` | Target request has certificate-error delegate event | Same class of verifier failure in Edge |
| Chrome ExpiredCRL HttpExpired | Completed without recorded `net_error` | No target certificate-error delegate event detected | This particular run did not report the same failure; do not generalize without timeline/cache-state verification |
| Edge UseMaxAge Warm | Target verifier job lacks completion | Outcome not established | Unknown, not success |

`-206` is Chromium's `ERR_CERT_REVOKED`; `-205` is `ERR_CERT_UNABLE_TO_CHECK_REVOCATION`. Numeric error codes are preserved in the source CSV. The delegate error event is a network-request-level observation, **not** direct proof of the displayed browser UI, whether the user clicked through, or final page load.

## Cross-layer triangulation

**Chrome revocation sequence:** CRL 213 (two revoked entries) precedes CRL 214 (three entries). The newly added serial `1F0000000BC7830B40FEA4D6C900000000000B` matches the leaf certificate recovered from the corresponding Chrome NetLog. The target-host verifier then records `-206`, and the target URL has an SSL certificate-error delegate event.

**Edge revocation sequence:** CRL 30 (one revoked entry) precedes CRL 31 (two entries). The newly added serial `1F00000009D1BDA863D77A4CA8000000000009` matches the leaf recovered from the corresponding Edge NetLog. The verifier records `-206`, and the target URL has certificate-error delegate events.

**Expired-CRL/HTTP-fresh condition:** Chrome and Edge verifier jobs both record `-205`. This supports the narrower statement that HTTP freshness alone did not produce a successful revocation verification in these controlled runs. The exact CRL expiry relative to the verifier timestamp, signature integrity and cache ownership should still be verified before making a broad implementation claim.

## Confidence and outstanding checks

**High confidence:** Parsed verifier codes in original NetLogs; matching leaf serials on captured issuing-CA CRLs (per earlier DER inventory); target URL certificate-error delegate events in the scenarios above.

**Moderate confidence:** Scenario-level triangulation of HTTP CRL retrieval, certificate serial and verifier outcome. This is correlation within controlled runs, not a complete per-request causality trace.

**Not established:** Visible browser warning, navigation final status, user override, whether OS or browser cache supplied a specific CRL, cryptographic verification of every recovered CRL signature, and causal effect of the load balancer (R29 not yet executed).

## Required further experiments

**R29 — HAProxy/IIS load-balancer tests (requires user-prepared Ubuntu VM):** Healthy baseline; single-backend failure (RST versus silent drop); two-backend failure; all-backend failure; backend recovery; VIP failure; stale-but-HTTP-healthy backend; consistent versus divergent CRL payloads. Capture HAProxy logs, packet traces, Windows validation results and cache state, with controlled leaf/CDP and identical CRL material. A basic HTTP 200 health check is insufficient to prove CRL validity or freshness.

**Optional focused repeat:** For the HTTP-fresh/cryptographically-expired CRL condition, capture original DER, HTTP response headers, absolute timestamps, verifier result and browser screenshot in one run, plus a no-cache control. This repeat is valuable for causal precision, but the current NetLogs already demonstrate `-205` in the two recorded scenarios.

## Reproducibility notes

The accompanying script `revocation_batch_audit.py` extracts the NetLog-level scenario evidence from the original archives. It requires Python and `cryptography`. The CSV contains a short `target_request_error_details` excerpt, while the JSON contains per-request and per-job records. Preserve originals and SHA-256 manifest. Event counts refer to source-level events, not unique user actions. Dependency-graph matching is best-effort and may miss implicit relationships or references encoded outside `source_dependency`.
