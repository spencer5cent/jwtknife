JWTKnife

JWTKnife is an interactive offensive security tool for testing JSON Web Token (JWT) authentication implementations. It is designed for learning, lab solving (e.g. PortSwigger Web Security Academy), and real-world security testing where JWT-based access control is in use.

The tool focuses on logic flaws and cryptographic weaknesses rather than brute-force endpoint scanning.

⸻

What JWTKnife Does

JWTKnife walks the tester through a structured JWT attack workflow:
	1.	Parses and inspects a supplied JWT
	2.	Establishes baseline access behavior
	3.	Attempts common JWT authentication bypass techniques
	4.	Detects weak HMAC secrets and forges admin tokens
	5.	Outputs forged tokens for manual or automated use

JWTKnife does not blindly send destructive requests. It gives the operator control over what happens after a token is forged.

⸻

Attack Phases

Phase 0 — Baseline Requests

JWTKnife sends three baseline requests using the original JWT:
	•	Public (no authentication required)
	•	Authenticated (JWT required)
	•	Admin-only endpoint

This establishes expected behavior and helps determine whether later attacks succeed.

⸻

Phase 1 — JWT Authentication Attacks

JWTKnife automatically attempts common JWT auth bypass techniques:
	•	Unverified signature attacks
	•	alg=none attacks
	•	Claim escalation attempts (sub, role-like values)

Each attempt is evaluated and reported with HTTP status and response characteristics.

⸻

Phase 2/3 — Weak HMAC Secret Recovery (HS256 / HS384 / HS512)

If the JWT uses an HMAC algorithm and signature enforcement is detected, JWTKnife offers to attempt secret recovery.

You can choose:
	1.	Built-in common JWT secrets
	2.	A custom wordlist (via hashcat)
	3.	Skip cracking entirely

If a secret is recovered, JWTKnife automatically forges a new JWT with escalated privileges (e.g. sub=administrator) and prints it.

This forged token is cryptographically valid.

⸻

JWT Placement Support

JWTKnife supports the most common JWT transport mechanisms:
	•	Authorization header (Authorization: Bearer <token>)
	•	Cookies
	•	Custom headers

The tool asks where the JWT is sent and injects it correctly for all test requests.

⸻

Post-Forged Token Workflow (By Design)

JWTKnife does not automatically perform destructive admin actions.

Instead, it intentionally:
	•	Prints the forged admin JWT
	•	Leaves final usage to the tester

This design allows you to:
	•	Paste the token into Burp
	•	Replay requests manually
	•	Use the token in other tools
	•	Solve labs cleanly without surprises

This keeps the tool safe, predictable, and flexible.

⸻

Why Raw HTTP Requests Were Removed

Earlier versions experimented with pasting raw HTTP requests directly into the terminal.

This was removed because:
	•	It is unsafe UX (can accidentally execute shell input)
	•	It causes terminal parsing issues
	•	File-based or post-forge usage is safer and clearer

Future support, if added, will be file-based, not inline pasting.

⸻

Typical Use Cases
	•	PortSwigger JWT labs
	•	Learning JWT attack patterns
	•	Testing internal applications
	•	Bug bounty JWT triage
	•	Red team tooling
	•	Teaching JWT security concepts

⸻

What JWTKnife Is NOT
	•	Not an automated exploit framework
	•	Not a brute-force web scanner
	•	Not a replacement for Burp
	•	Not a mass vulnerability scanner

JWTKnife is intentionally focused and opinionated.

⸻

Security & Ethics

JWTKnife is intended for:
	•	Authorized testing
	•	Labs and learning environments
	•	Security research
	•	Defensive validation

Do not use against systems you do not own or have permission to test.

⸻

Repository Status
	•	Private repository
	•	Actively developed
	•	Built for clarity and correctness over speed
	•	Designed to evolve (POST/PUT support planned)

⸻
PortSwigger JWT Labs Coverage

- [x] JWT authentication bypass via unverified signature  
- [x] JWT authentication bypass via flawed signature verification  
- [x] JWT authentication bypass via weak signing key  
- [x] JWT authentication bypass via jwk header injection  
- [ ] JWT authentication bypass via jku header injection  
- [ ] JWT authentication bypass via kid header path traversal  
- [ ] JWT authentication bypass via algorithm confusion  
- [ ] JWT authentication bypass via algorithm confusion with no exposed key

⸻

Credits

Built by spencer5cent
With iterative design, testing, and refinement through real-world JWT lab solving.
