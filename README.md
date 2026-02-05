JWTKnife

JWTKnife is an interactive offensive security tool for testing JSON Web Token (JWT) authentication implementations.
It is designed for learning, lab solving (e.g. PortSwigger Web Security Academy), and real-world security testing where JWT-based access control is in use.

JWTKnife focuses on logic flaws and cryptographic weaknesses, not endpoint brute-forcing or mass scanning.

⸻

## What JWTKnife Does

JWTKnife walks the tester through a structured JWT attack workflow:

1. Parses and inspects a supplied JWT  
2. Establishes baseline access behavior  
3. Automatically attempts common JWT authentication bypass techniques  
4. Detects weak cryptographic assumptions and forges alternative tokens  
5. Reports what actually worked, conservatively and repeatably  

JWTKnife is intentionally operator-driven — it does not guess, assume success, or silently perform destructive actions.

⸻

Attack Phases

Phase 0 — Baseline Requests

JWTKnife sends three baseline requests using the original JWT:
	•	Public (no authentication required)
	•	Authenticated (JWT required)
	•	Admin-only endpoint

This establishes expected behavior and prevents false positives in later phases.

⸻

Phase 1 — JWT Authentication Attacks

JWTKnife automatically attempts common JWT auth bypass techniques, including:
	•	Unverified signature attacks
	•	alg=none attacks
	•	RSA → HMAC algorithm confusion
	•	JWK header injection
	•	JKU header injection (user-assisted)
	•	kid header manipulation

Each attempt is evaluated relative to the baseline, not guessed based on endpoint names.

Success is only reported when clear authorization changes occur (2xx or meaningful 3xx differences).

⸻

Phase 2/3 — Weak HMAC Secret Recovery (HS256 / HS384 / HS512)

If the JWT uses an HMAC algorithm and signature enforcement is detected, JWTKnife can attempt secret recovery.

You can choose:
	1.	Built-in common JWT secrets
	2.	A custom wordlist (via hashcat integration)
	3.	Skip cracking entirely

If a secret is recovered, JWTKnife forges a cryptographically valid JWT with escalated claims and reports it.

⸻

Algorithm Confusion Support (Real-World Safe)

JWTKnife detects asymmetric JWTs (RS* / ES*) and attempts algorithm confusion safely:
	•	Discovers public keys via:
	•	/jwks.json
	•	/.well-known/jwks.json
	•	OpenID discovery (jwks_uri)
	•	Tries multiple real-world HMAC interpretations:
	•	Raw PEM
	•	Base64-encoded PEM
	•	Tests multiple admin-style identities (administrator, admin, etc.)
	•	Verifies success against baseline responses

Lab-specific behavior is clearly labeled, never assumed.

⸻

JWT Placement Support

JWTKnife supports common JWT transport mechanisms:
	•	Authorization: Bearer <token>
	•	Cookies
	•	Custom headers

The tool asks once and injects correctly for all requests.

⸻

Post-Exploit Behavior (By Design)

JWTKnife does not automatically perform destructive actions.

Instead, it:
	•	Prints the forged JWT
	•	Shows the HTTP response that proved success
	•	Leaves final actions to the operator

This allows safe usage with Burp, curl, browsers, or other tooling.

⸻

What JWTKnife Is NOT
	•	❌ Not a mass vulnerability scanner
	•	❌ Not a brute-force web fuzzer
	•	❌ Not a Burp replacement
	•	❌ Not an auto-exploitation framework

JWTKnife is focused, conservative, and transparent by design.

⸻

Security & Ethics

JWTKnife is intended for:
	•	Authorized security testing
	•	Labs and learning environments
	•	Security research
	•	Defensive validation

Do not use against systems you do not own or have permission to test.

⸻

Repository Status
	•	Private repository
	•	Actively developed
	•	Built for correctness over speed
	•	Designed to evolve (method expansion planned)

⸻

JWT Lab Coverage (Reference)
	•	Unverified signature
	•	alg=none
	•	Weak HMAC signing key
	•	JWK header injection
	•	Algorithm confusion (RSA → HMAC)
	•	Algorithm confusion with JWKS discovery
	•	[~] JKU header injection (requires hosted JWKS)
	•	[~] kid path traversal (target-dependent)

⸻

Credits

Built by spencer5cent
Through iterative design, debugging, and real-world JWT attack validation.
JWTKnife

JWTKnife is an interactive offensive security tool for testing JSON Web Token (JWT) authentication implementations.
It is designed for learning, lab solving (e.g. PortSwigger Web Security Academy), and real-world security testing where JWT-based access control is in use.

JWTKnife focuses on logic flaws and cryptographic weaknesses, not endpoint brute-forcing or mass scanning.

⸻

What JWTKnife Does

JWTKnife guides the tester through a structured JWT attack workflow:
1. Parses and inspects one or more JWTs
2. Establishes baseline access behavior
3. Automatically attempts JWT authentication bypass techniques
4. Recovers or reuses signing material where possible
5. Forges and safely validates privileged tokens
6. Reports what actually worked, conservatively and repeatably

JWTKnife is intentionally operator-driven — it does not guess, assume success, or silently perform destructive actions.

⸻

Attack Phases

Phase 0 — Baseline Requests

JWTKnife establishes baseline behavior using the original JWT:
• Public endpoint
• Authenticated endpoint
• Admin or privilege-escalated endpoint

This prevents false positives and ensures later attacks are evaluated correctly.

⸻

Phase 1 — JWT Authentication Attacks (Automatic)

JWTKnife automatically attempts common JWT auth bypass techniques, including:
• Unverified signature bypass
• alg=none bypass
• Weak HMAC misuse
• Algorithm confusion (RS*/ES* → HS*)
• Algorithm confusion with no exposed key (sig2n-style)
• JWK header injection
• JKU header injection
• kid header manipulation

By default, execution short-circuits on the first confirmed success.

Use the `--exhaustive` flag to force all attacks to run regardless of success.

⸻

Algorithm Confusion Support (Advanced)

JWTKnife supports both real-world algorithm confusion variants:

With exposed key:
• Discovers public keys via:
  • /jwks.json
  • /.well-known/jwks.json
  • OpenID discovery (jwks_uri)
• Reuses keys as HMAC secrets
• Tries multiple interpretations (raw PEM, base64 PEM)
• Tests multiple admin-style identities
• Verifies success against baseline behavior

Without exposed key (sig2n-style):
• Accepts two server-issued JWTs
• Automatically recovers the RSA public key using external tooling
• Validates the recovered key
• Forges a valid HS256 admin token
• Confirms access before reporting success

Lab-specific behavior is clearly labeled and never assumed.

⸻

JWT Input Flexibility

JWTs can be provided via:
• Terminal paste
• File input (auto-extracts JWTs)
• Optional second JWT for advanced alg-confusion attacks

⸻

JWT Placement Support

JWTKnife supports common JWT transport mechanisms:
• Authorization: Bearer <token>
• Cookies
• Custom headers

The tool asks once and injects correctly for all requests.

⸻

Post-Exploit Behavior (By Design)

JWTKnife does not automatically perform destructive actions.

Instead, it:
• Prints the forged JWT
• Shows the HTTP response that proved success
• Leaves final actions to the operator

This keeps usage safe, predictable, and compatible with Burp, curl, browsers, or other tools.

⸻

What JWTKnife Is NOT

• Not a mass vulnerability scanner
• Not a brute-force web fuzzer
• Not a Burp replacement
• Not an auto-exploitation framework

JWTKnife is focused, conservative, and transparent by design.

⸻

Security & Ethics

JWTKnife is intended for:
• Authorized security testing
• Labs and learning environments
• Security research
• Defensive validation

Do not use against systems you do not own or have permission to test.

⸻

Repository Status

• Private repository
• Actively developed
• Built for correctness over speed
• Designed to evolve

⸻

PortSwigger JWT Lab Coverage

• Unverified signature
• alg=none
• Weak HMAC signing key
• JWK header injection
• JKU header injection
• kid header path traversal
• Algorithm confusion (exposed key)
• Algorithm confusion (no exposed key / sig2n)

⸻

Credits

Built by spencer5cent
Through iterative design, debugging, and real-world JWT attack validation.
