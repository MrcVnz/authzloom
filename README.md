# AuthzLoom

I built AuthzLoom to make authorization testing easier to repeat and easier to
review. You describe the identities, controlled objects and operation you want
to test. AuthzLoom builds the matrix, runs it within the limits you set and
keeps redacted evidence of what happened.

It works with REST and GraphQL and can be used from the command line, through
MCP, through its local HTTP API or with the optional Burp Suite extension.

AuthzLoom does not decide whether something is a vulnerability and it does not
assign severity. It collects evidence. The final judgment stays with the
person reviewing the result.

## What it protects

Authorization testing can change data, so I designed the tool around explicit
limits:

- Every scenario defines its allowed hosts, methods, request budget and rate.
- Every request goes through the same policy validation, including identity
  probes.
- An operation that changes state must have a readback step.
- Cleanup runs after a mutation may have been sent, even when the case fails or
  is cancelled.
- Direct connections are limited to local labs and never follow redirects.
- Traffic to anything outside the local machine must use a Burp or CDP session
  controlled by the operator.
- Live credentials do not belong in scenario files. Burp keeps the original
  request and gives Python an opaque `cap_*` handle instead.
- Local runs stay local. Exported capsules are redacted and never contain raw
  Burp capture bytes.

Only use AuthzLoom on systems you own or have explicit permission to test.

## Installation

You need Python 3.11 or newer.

On Windows:

```powershell
git clone <repository-url> authzloom
cd authzloom
powershell -ExecutionPolicy Bypass -File ./setup-env.ps1 -Dev
```

If you already manage your own Python environment:

```bash
python -m pip install -e '.[dev]'
```

The optional dependency groups are `yaml`, `cdp` and `dev`.

## Try it from the command line

The included example expects a synthetic service on `127.0.0.1:8877`.
Validation and planning are offline. Running the scenario requires the local
lab service.

```powershell
./.venv/Scripts/authzloom.exe init ./scenario.json
./.venv/Scripts/authzloom.exe validate ./examples/rest.json
./.venv/Scripts/authzloom.exe plan ./examples/rest.json --explain
./.venv/Scripts/authzloom.exe run ./examples/rest.json
./.venv/Scripts/authzloom.exe status
./.venv/Scripts/authzloom.exe export <RUN_ID> --output capsule.redacted.json
./.venv/Scripts/authzloom.exe schema > schemas/scenario.v1.json
```

There is also a GraphQL example in `examples/graphql.json`. To see structured
logs without secrets, set `AUTHZLOOM_LOG=1`.

You can run the module directly too:

```powershell
./.venv/Scripts/python.exe -m authzloom.cli --help
```

## Using AuthzLoom with an AI client

AuthzLoom includes an MCP server:

```powershell
./.venv/Scripts/authzloom.exe mcp
```

For an installed registry package, the canonical package launcher is:

```bash
uvx authzloom
```

The explicit `uvx authzloom mcp` form and the `authzloom-mcp` entry point remain
available for compatibility. Catalogs and managed launchers should identify the
`authzloom` package; invoking the package without a CLI subcommand starts MCP
over standard input and output.

MCP communicates over standard input and output. If you start it by hand, it
will appear to wait silently. That is expected. Normally, your MCP client
starts and controls the process:

```json
{
  "mcpServers": {
    "authzloom": {
      "command": "C:/absolute/path/authzloom/.venv/Scripts/python.exe",
      "args": ["-m", "authzloom.cli", "mcp"],
      "env": {
        "AUTHZLOOM_DATA_DIR": "C:/absolute/path/authzloom/.authzloom"
      }
    }
  }
}
```

The available tools are `authzloom_ingest`, `authzloom_plan`,
`authzloom_run`, `authzloom_status` and `authzloom_export`. Always plan a
scenario before running it.

## Using the Burp extension

Burp Suite is not included. Point `BURP_JAR` to your local Burp installation,
build the extension and start the launcher:

```powershell
$env:BURP_JAR = 'C:\path\to\burpsuite.jar'
powershell -ExecutionPolicy Bypass -File ./burp-extension/build.ps1
powershell -ExecutionPolicy Bypass -File ./start-authzloom-burp.ps1
```

Load `burp-extension/build/authzloom-burp.jar` through Burp's extension
settings if it is not already loaded.

The launcher creates a temporary shared token, starts the local API on
`127.0.0.1:8891` and opens Burp. The extension runs its replay bridge on
`127.0.0.1:8892` and adds **Send to AuthzLoom** to Burp's context menu.

When you send a request to AuthzLoom, the live bytes stay inside Burp. Python
receives the host, method, path and an opaque handle. During replay, only an
allowlisted overlay is applied. Authorization and Cookie headers remain under
Burp's control.

The local API provides `GET /health`, `GET /ready` and `GET /version`.
`/status` accepts `limit` and `offset`. It only binds to loopback.

## Development

Run the complete local check before submitting a change:

```powershell
powershell -ExecutionPolicy Bypass -File ./verify-integration.ps1
```

Please keep the public repository independent. Private paths, client
configuration, target evidence, credentials and generated run data should
never be committed.

## License

AuthzLoom is available under the MIT License. See [LICENSE](LICENSE).
