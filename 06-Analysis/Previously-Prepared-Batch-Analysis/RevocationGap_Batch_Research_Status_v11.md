# The Revocation Gap — Batch Research Status (v1.1)

## Completed from existing evidence

- **R01–R28 Windows CryptoAPI:** Previously inventoried and packet-audited; detailed behavior claims remain scoped to each recorded condition and must not be generalized across OS versions without independent testing.
- **Chrome/Edge NetLogs:** 30 original JSON logs parsed. Browser HTTP 200/304 evidence and cache-control observations retained from prior analyses.
- **CRL DER recovery:** Previously recovered and parsed CRL payloads; subsequent analysis inventories 28 CRL response records from 16 capture scenarios (counts describe different units).
- **CRL version and revoked serial changes:** Chrome 213→214 and Edge 30→31 documented.
- **Leaf identity:** Newly revoked serial matches the corresponding NetLog leaf certificate in both revocation sequences.
- **Verifier outcome:** Chrome and Edge revocation `-206`; HTTP-fresh expired-CRL `-205`; one Edge warm verifier result incomplete.
- **NEW v1.1:** Independent audit of 30 NetLogs for target URL request starts, SSL certificate-error delegate events and explicit source-dependency graph. Six error scenarios have URL certificate-error events; 21 verifier jobs are graph-connected to a target URL request, but not the six error scenarios.

## Not yet done / cannot be done from available evidence alone

1. **R29 physical HAProxy experiment:** Needs Ubuntu VM, lab network, test certificate with load-balanced CDP, backend failure injection, packet capture and synchronized timestamps. No results exist yet.
2. **Browser UI outcome:** A NetLog verifier error and request-level certificate-error event are not substitutes for a screenshot or explicit final navigation-state trace.
3. **End-to-end signature validation of every recovered CRL:** Requires recovered DER and matching CA certificates/chain with explicit signature verification; earlier parsing is not itself signature verification.
4. **OS-version comparison:** No equivalent Windows 11 test series in the provided R01–R28 evidence.
5. **Precise per-URL timeout generalization:** Existing lab observations apply to their particular network failure and cache conditions, not a universal fixed timeout.

## Writing readiness

The browser findings chapter can be drafted now with explicit observed/interpretation/limitations labels. Architecture recommendations can be drafted as hypotheses and engineering guidance, not experimentally proven load-balancer benefits. The R29 results section remains intentionally blank until the real experiment.

## Input/output manifest

Inputs: `Evidence-Chrome.zip`, `Evidence-Edge.zip`, prior v0.8–v1.0 research tables. New outputs: `RevocationGap_Browser_Navigation_Audit_v11.csv`, `RevocationGap_Browser_Navigation_Details_v11.json`, `RevocationGap_Consolidated_Browser_Findings_v11.md`, `RevocationGap_Batch_Research_Status_v11.md`, `revocation_batch_audit.py`.
