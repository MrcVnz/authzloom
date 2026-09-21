# Security policy

If you believe you found a security issue in AuthzLoom, please contact me
privately through the security contact configured on GitHub.

Tell me which version you tested, what boundary you believe was crossed and
how I can reproduce it in a local lab. Please do not test a suspected
AuthzLoom issue against someone else's system.

Do not include live credentials, cookies, access tokens, private target data
or raw run artifacts in a public issue.

## What counts as an AuthzLoom security issue

I consider failures in these controls part of AuthzLoom's security boundary:

- host and method restrictions;
- rate and request budget enforcement;
- protection of runtime credentials and Burp capture bytes;
- cleanup and cancellation behavior;
- redaction of stored and exported evidence;
- confinement of run data to the configured data directory.

Whether a target behavior is a vulnerability is outside this boundary.
AuthzLoom records evidence but does not make that decision.

## Threat model

AuthzLoom trusts the operator, the scenario they approved and the Burp or CDP
session they selected. It does not trust target responses, ingest payloads,
redirect locations or callers that are not controlled by the operator.

The following guarantees should always hold:

- Direct transport never opens a connection outside loopback, even through a
  redirect, URL credentials or an alternate spelling of localhost.
- Identity probes follow the same host, method and transport policy as every
  other request.
- Live request bytes and cookies remain in Burp. Python stores opaque handles,
  metadata and redacted evidence.
- Run IDs follow a strict format and cannot escape the configured data
  directory.
- Exported capsules do not expose secrets from structured bodies, forms, JWTs,
  Basic authentication, encoded captures or URLs.
