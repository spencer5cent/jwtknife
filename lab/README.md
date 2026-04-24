### JWT Lab Harness

This directory contains the local JWT lab used to regression-test `jwtknife`.

Files:
- `jwt_lab.py`: vulnerable local JWT target on `127.0.0.1:5005`
- `run_jwtknife_tests.py`: acceptance sweep against the current `jwtknife` binary
- `requirements.txt`: Python dependencies

Quick start:

```bash
python3 -m venv .venv
.venv/bin/pip install -r lab/requirements.txt
.venv/bin/python lab/jwt_lab.py
python3 lab/run_jwtknife_tests.py
```

What it covers:
- unverified signature
- `alg=none`
- weak HMAC
- `kid` traversal
- RSA to HMAC confusion via exposed JWKS
- RSA to HMAC confusion via `sig2n`
- `jwk`
- `jku`
- placement checks for bearer/cookie/custom header
- a POST-only regression case
