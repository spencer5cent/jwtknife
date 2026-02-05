## Overview

JWTKnife is an interactive tool for testing JWT-based authentication and authorization.
It’s built for learning, lab work (PortSwigger, etc.), and real-world testing where JWT logic or crypto decisions matter.

The goal is not coverage or speed — it’s correctness.
JWTKnife is designed to help you understand *why* a JWT attack works, not just whether it does.

## How It Works

JWTKnife follows a deliberate, step-by-step workflow:

1. Parse and inspect the supplied JWT
2. Establish baseline behavior using known-good and restricted endpoints
3. Attempt common JWT authentication bypass techniques
4. Detect weak cryptographic assumptions and reuse or recover signing material
5. Forge alternative tokens only when there’s clear proof they work

Nothing is assumed. Every result is verified against baseline responses.

JWTKnife is intentionally operator-driven. It won’t silently exploit anything or pretend a bypass worked when it didn’t.

## Attack Flow

### Baseline Requests

Before attempting any attacks, JWTKnife sends a small set of baseline requests:
- An endpoint that should be public
- An endpoint that requires authentication
- An endpoint that requires elevated or admin access

These responses define expected behavior and are used to validate all later results.

### JWT Authentication Attacks

JWTKnife automatically tests common JWT failure modes, including:
- Unverified signatures
- `alg=none`
- RSA → HMAC algorithm confusion
- JWK and JKU header injection
- `kid` header manipulation

Each attempt is compared directly to the baseline.  
A technique is only marked successful if there’s a real authorization change.

### HMAC Secret Recovery (Optional)

When HMAC-based JWTs are detected and signature enforcement is in place, JWTKnife can attempt to recover weak signing secrets.

You can choose to:
- Use built-in common JWT secrets
- Supply a custom wordlist
- Skip cracking entirely

Recovered secrets are used to forge a valid token and re-tested before being reported.

### Algorithm Confusion (Real Targets)

For asymmetric JWTs, JWTKnife handles algorithm confusion carefully:

- Public keys are discovered via common real-world locations (`jwks.json`, OpenID discovery, etc.)
- Multiple HMAC interpretations are tested (raw PEM, base64-encoded)
- Privileged identities are tried conservatively
- Success is confirmed against baseline behavior

Lab-specific shortcuts are clearly labeled and never assumed to apply to real targets.

## Token Placement

JWTKnife supports the following:
- `Authorization: Bearer`
- Cookies
- Custom headers

You specify this once and it’s applied consistently.


## Notes

This is not a scanner, and it’s not meant to replace Burp or nuclei.
It’s a focused tool for JWT logic and crypto failures, built to be predictable and honest about results.

## Usage

JWTKnife is intended for environments you’re authorized to test:
labs, learning environments, research targets, and defensive validation.

Repository is private and under active development.
