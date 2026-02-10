JWTKnife is an interactive CLI tool for testing JWT-based authentication and authorization.

It inspects a JWT, sends baseline requests, and tests common JWT weaknesses such as:
- alg=none
- Missing or unverified signatures
- RSA → HMAC algorithm confusion
- kid, jwk, and jku header manipulation
- Weak HMAC signing secrets (optional wordlist-based testing)

JWTKnife supports JWTs sent via:
- Authorization: Bearer header
- Cookies
- Custom headers

All tests are checked against baseline responses so results reflect real authorization behavior.

Usage:

Run the tool and follow the prompts:

./jwtknife

You will be prompted to:
- Provide a JWT (paste or load from file)
- Choose where the JWT is sent
- Define baseline endpoints
- Select which tests to run
