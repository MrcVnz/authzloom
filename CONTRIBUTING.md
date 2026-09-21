# Contributing

Thanks for taking the time to improve AuthzLoom.

I prefer changes that are small enough to review properly and easy to test in
a local lab. If your change affects how requests are sent, stored or redacted,
please explain the security boundary it touches in the pull request.

Before opening a pull request:

1. Prepare the development environment with
   `powershell -ExecutionPolicy Bypass -File ./setup-env.ps1 -Dev`.
2. Run `powershell -ExecutionPolicy Bypass -File ./verify-integration.ps1`.
3. Run `python -m authzloom.bench` if the change touches execution, storage or
   redaction.
4. Check that no credentials or `.authzloom` run data were included.

Some behavior is intentionally strict. Please do not weaken the loopback limit
for direct connections, scenario planning, request budgets, readback, cleanup,
redaction or opaque Burp capture handles for convenience or performance.

AuthzLoom should continue to produce evidence rather than conclusions. It must
not label a result as a vulnerability, assign severity or recommend submitting
a report.
