from flask import Flask, request, jsonify, make_response
import jwt
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jwt.algorithms import RSAAlgorithm
import requests

app = Flask(__name__)

HS_SECRET = "weaksecret"
HS_KID_SECRET = "kidsecret"
NULL_SECRET = b"\x00"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIV_PEM = RSA_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
RSA_PUB_PEM = RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
RSA_PUB_DER = RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
RSA_PUB_PEM_B64 = base64.b64encode(RSA_PUB_PEM).decode()

SERVER_KID = "server-kid"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jwk_from_public_key(pub_key, kid=None):
    numbers = pub_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    if kid:
        jwk["kid"] = kid
    return jwk

SERVER_JWK = jwk_from_public_key(RSA_KEY.public_key(), SERVER_KID)


def get_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    if request.cookies.get("session"):
        return request.cookies.get("session")
    if request.headers.get("X-Auth"):
        return request.headers.get("X-Auth")
    return None


def ok_public(mode):
    return jsonify({"mode": mode, "public": True})


def ok_auth(mode, sub):
    return jsonify({"mode": mode, "auth": True, "sub": sub})


def ok_admin(mode, sub):
    return jsonify({"mode": mode, "admin": True, "sub": sub})


def fail(status, msg):
    return make_response(jsonify({"error": msg}), status)


def issue_hs(sub="wiener"):
    return jwt.encode({"sub": sub, "iat": int(time.time())}, HS_SECRET, algorithm="HS256")


def issue_algnone(sub="wiener"):
    return jwt.encode({"sub": sub, "iat": int(time.time())}, HS_SECRET, algorithm="HS256")


def issue_kid(sub="wiener"):
    return jwt.encode({"sub": sub, "iat": int(time.time())}, HS_KID_SECRET, algorithm="HS256", headers={"kid": "goodkid"})


def issue_rs(sub="wiener", extra=None):
    payload = {"sub": sub, "iat": int(time.time())}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, RSA_PRIV_PEM, algorithm="RS256", headers={"kid": SERVER_KID})


def decode_noverify(token):
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False}, algorithms=["none", "HS256", "RS256"])


def hdr(token):
    return jwt.get_unverified_header(token)


def validate_unverified(token):
    return decode_noverify(token)


def validate_alg_none(token):
    h = hdr(token)
    if h.get("alg") == "none":
        return decode_noverify(token)
    return jwt.decode(token, HS_SECRET, algorithms=["HS256"])


def validate_weak_hmac(token):
    return jwt.decode(token, HS_SECRET, algorithms=["HS256"])


def validate_kid(token):
    h = hdr(token)
    kid = h.get("kid", "")
    if kid in ["../../../../../../../dev/null", "/dev/null", "..\\..\\..\\..\\..\\..\\..\\NUL"]:
        return jwt.decode(token, NULL_SECRET, algorithms=["HS256"])
    return jwt.decode(token, HS_KID_SECRET, algorithms=["HS256"])


def validate_rs_jwks_conf(token):
    h = hdr(token)
    if h.get("alg") == "HS256":
        last_err = None
        for secret in [RSA_PUB_PEM, RSA_PUB_PEM_B64.encode()]:
            try:
                return jwt.decode(token, secret, algorithms=["HS256"])
            except Exception as e:
                last_err = e
        raise last_err
    return jwt.decode(token, RSA_PUB_PEM, algorithms=["RS256"])


def validate_rs_sig2n_conf(token):
    h = hdr(token)
    if h.get("alg") == "HS256":
        return jwt.decode(token, RSA_PUB_DER, algorithms=["HS256"])
    return jwt.decode(token, RSA_PUB_PEM, algorithms=["RS256"])


def validate_jwk(token):
    h = hdr(token)
    if "jwk" in h:
        pub = RSAAlgorithm.from_jwk(json.dumps(h["jwk"]))
        return jwt.decode(token, pub, algorithms=["RS256"])
    return jwt.decode(token, RSA_PUB_PEM, algorithms=["RS256"])


def validate_jku(token):
    h = hdr(token)
    if h.get("jku"):
        r = requests.get(h["jku"], timeout=3)
        r.raise_for_status()
        jwks = r.json()
        wanted = h.get("kid")
        for key in jwks.get("keys", []):
            if wanted is None or key.get("kid") == wanted:
                pub = RSAAlgorithm.from_jwk(json.dumps(key))
                return jwt.decode(token, pub, algorithms=["RS256"])
        raise Exception("kid not found in remote jwks")
    return jwt.decode(token, RSA_PUB_PEM, algorithms=["RS256"])


VALIDATORS = {
    "unverified": validate_unverified,
    "algnone": validate_alg_none,
    "weakhmac": validate_weak_hmac,
    "kid": validate_kid,
    "rsa-jwks-conf": validate_rs_jwks_conf,
    "rsa-sig2n": validate_rs_sig2n_conf,
    "jwk": validate_jwk,
    "jku": validate_jku,
}

ISSUERS = {
    "unverified": issue_hs,
    "algnone": issue_algnone,
    "weakhmac": issue_hs,
    "kid": issue_kid,
    "rsa-jwks-conf": issue_rs,
    "rsa-sig2n": issue_rs,
    "jwk": issue_rs,
    "jku": issue_rs,
}


def handle(mode, need_admin=False):
    token = get_token()
    if not token:
        return fail(401, "missing token")
    try:
        claims = VALIDATORS[mode](token)
    except Exception as e:
        return fail(401, f"invalid token: {e}")
    sub = claims.get("sub", "")
    if need_admin and sub not in {"administrator", "admin", "root", "superuser", "carlos"}:
        return fail(403, "not admin")
    if need_admin:
        return ok_admin(mode, sub)
    return ok_auth(mode, sub)


@app.get('/attacker/jwks.json')
def attacker_jwks():
    try:
        with open('/tmp/attacker-jwks.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return fail(404, 'no hosted jwks yet')
    return jsonify(data)


@app.get('/<mode>/')
def public(mode):
    if mode not in VALIDATORS:
        return fail(404, 'unknown mode')
    return ok_public(mode)


@app.get('/<mode>/issue')
def issue(mode):
    if mode not in VALIDATORS:
        return fail(404, 'unknown mode')
    sub = request.args.get('sub', 'wiener')
    token1 = ISSUERS[mode](sub)
    out = {"token": token1}
    if mode == 'rsa-sig2n':
        out["second_token"] = issue_rs(sub, extra={"nonce": int(time.time())})
    if mode == 'rsa-jwks-conf':
        out["jwks"] = {"keys": [SERVER_JWK]}
    return jsonify(out)


@app.get('/<mode>/.well-known/openid-configuration')
def oidc(mode):
    if mode != 'rsa-jwks-conf':
        return fail(404, 'not found')
    return jsonify({"jwks_uri": "/rsa-jwks-conf/jwks.json"})


@app.get('/<mode>/jwks.json')
def jwks(mode):
    if mode != 'rsa-jwks-conf':
        return fail(404, 'not found')
    return jsonify({"keys": [SERVER_JWK]})


@app.route('/<mode>/me', methods=['GET', 'POST'])
def me(mode):
    if mode not in VALIDATORS:
        return fail(404, 'unknown mode')
    return handle(mode, need_admin=False)


@app.route('/<mode>/admin', methods=['GET', 'POST'])
def admin(mode):
    if mode not in VALIDATORS:
        return fail(404, 'unknown mode')
    return handle(mode, need_admin=True)


@app.route('/post-only/weakhmac/admin', methods=['POST'])
def post_admin_wh():
    token = get_token()
    if not token:
        return fail(401, 'missing token')
    try:
        claims = validate_weak_hmac(token)
    except Exception as e:
        return fail(401, f'invalid token: {e}')
    sub = claims.get('sub', '')
    if sub not in {'administrator', 'admin'}:
        return fail(403, 'not admin')
    return ok_admin('post-only-weakhmac', sub)


@app.route('/post-only/weakhmac/me', methods=['POST'])
def post_me_wh():
    token = get_token()
    if not token:
        return fail(401, 'missing token')
    try:
        claims = validate_weak_hmac(token)
    except Exception as e:
        return fail(401, f'invalid token: {e}')
    return ok_auth('post-only-weakhmac', claims.get('sub', ''))


@app.route('/post-only/weakhmac/', methods=['GET'])
def post_public_wh():
    return ok_public('post-only-weakhmac')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5005, threaded=True)
