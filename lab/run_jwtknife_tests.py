import json
import subprocess
import requests
from pathlib import Path

BASE = 'http://127.0.0.1:5005'
BIN = '/tmp/jwtknife'
OUT = []


def run(args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def issue(mode, sub='wiener'):
    r = requests.get(f'{BASE}/{mode}/issue', params={'sub': sub}, timeout=5)
    r.raise_for_status()
    return r.json()


def run_case(name, mode, extra_args=None, expect_success=True):
    data = issue(mode)
    token = data['token']
    args = [BIN, '--non-interactive', '--output', 'json', '--jwt', token,
            '--public-url', f'{BASE}/{mode}/', '--auth-url', f'{BASE}/{mode}/me', '--admin-url', f'{BASE}/{mode}/admin']
    if extra_args:
        args.extend(extra_args)
    code, stdout, stderr = run(args)
    result = {'name': name, 'code': code, 'stderr': stderr.strip()}
    if code == 0:
        obj = json.loads(stdout)
        result['auth_state'] = obj.get('AuthState')
        result['attacks'] = {a['ID']: a['Outcome'] for a in obj.get('JWTAttacks', [])}
        result['successes'] = [a['ID'] for a in obj.get('JWTAttacks', []) if a['Outcome'] == 'success']
    OUT.append(result)


def run_jku_case():
    data = issue('jku')
    token = data['token']
    base_args = [BIN, '--non-interactive', '--output', 'json', '--jwt', token,
                 '--public-url', f'{BASE}/jku/', '--auth-url', f'{BASE}/jku/me', '--admin-url', f'{BASE}/jku/admin']
    code1, stdout1, stderr1 = run(base_args)
    result = {'name': 'jku-two-step', 'step1_code': code1, 'step1_stderr': stderr1.strip()}
    if code1 != 0:
        OUT.append(result)
        return
    obj1 = json.loads(stdout1)
    jku_steps = [a for a in obj1['JWTAttacks'] if a['ID'] == 'jku-header-injection']
    result['step1_outcome'] = jku_steps[0]['Outcome'] if jku_steps else None
    jwks_text = jku_steps[0]['Steps'][0]['JWT']['Token']
    Path('/tmp/attacker-jwks.json').write_text(jwks_text)
    callback = f'{BASE}/attacker/jwks.json'
    code2, stdout2, stderr2 = run(base_args + ['--callback-url', callback])
    result['step2_code'] = code2
    result['step2_stderr'] = stderr2.strip()
    if code2 == 0:
        obj2 = json.loads(stdout2)
        result['successes'] = [a['ID'] for a in obj2.get('JWTAttacks', []) if a['Outcome'] == 'success']
        result['attacks'] = {a['ID']: a['Outcome'] for a in obj2.get('JWTAttacks', [])}
    OUT.append(result)


def run_cookie_and_header_smoke():
    data = issue('weakhmac')
    token = data['token']
    for placement, name in [('cookie', 'session'), ('header', 'X-Auth')]:
        args = [BIN, '--non-interactive', '--output', 'json', '--jwt', token,
                '--placement', placement, '--placement-name', name,
                '--hmac-secret', 'weaksecret',
                '--public-url', f'{BASE}/weakhmac/', '--auth-url', f'{BASE}/weakhmac/me', '--admin-url', f'{BASE}/weakhmac/admin']
        code, stdout, stderr = run(args)
        result = {'name': f'placement-{placement}', 'code': code, 'stderr': stderr.strip()}
        if code == 0:
            obj = json.loads(stdout)
            result['successes'] = [a['ID'] for a in obj.get('JWTAttacks', []) if a['Outcome'] == 'success']
            result['attacks'] = {a['ID']: a['Outcome'] for a in obj.get('JWTAttacks', [])}
        OUT.append(result)


def run_post_regression():
    data = issue('weakhmac')
    token = data['token']
    args = [BIN, '--non-interactive', '--output', 'json', '--jwt', token,
            '--hmac-secret', 'weaksecret', '--method', 'POST',
            '--public-url', f'{BASE}/post-only/weakhmac/', '--auth-url', f'{BASE}/post-only/weakhmac/me', '--admin-url', f'{BASE}/post-only/weakhmac/admin']
    code, stdout, stderr = run(args)
    result = {'name': 'post-only-weakhmac', 'code': code, 'stderr': stderr.strip()}
    if code == 0:
        obj = json.loads(stdout)
        result['baseline'] = {k.lower(): v['Status'] for k, v in obj['Baseline'].items()}
        result['attacks'] = {a['ID']: a['Outcome'] for a in obj.get('JWTAttacks', [])}
        wh = [a for a in obj['JWTAttacks'] if a['ID'] == 'weak-hmac'][0]
        result['weak_hmac_note'] = wh.get('Note')
        result['weak_hmac_steps'] = [s.get('HTTP', {}).get('Status') if s.get('HTTP') else None for s in wh.get('Steps', [])]
    OUT.append(result)


run_case('unverified', 'unverified')
run_case('algnone', 'algnone')
run_case('weakhmac', 'weakhmac', ['--hmac-secret', 'weaksecret'])
run_case('kid', 'kid')
run_case('rsa-jwks-conf', 'rsa-jwks-conf', ['--exhaustive'])
# use jwt-file / second-jwt-file on sig2n smoke
sig = issue('rsa-sig2n')
Path('/tmp/sig2n.jwt').write_text(sig['token'])
Path('/tmp/sig2n-second.jwt').write_text(sig['second_token'])
code, stdout, stderr = run([BIN, '--non-interactive', '--output', 'json', '--jwt-file', '/tmp/sig2n.jwt', '--second-jwt-file', '/tmp/sig2n-second.jwt', '--public-url', f'{BASE}/rsa-sig2n/', '--auth-url', f'{BASE}/rsa-sig2n/me', '--admin-url', f'{BASE}/rsa-sig2n/admin', '--exhaustive'])
result = {'name': 'rsa-sig2n', 'code': code, 'stderr': stderr.strip()}
if code == 0:
    obj = json.loads(stdout)
    result['successes'] = [a['ID'] for a in obj.get('JWTAttacks', []) if a['Outcome'] == 'success']
    result['attacks'] = {a['ID']: a['Outcome'] for a in obj.get('JWTAttacks', [])}
OUT.append(result)
run_case('jwk', 'jwk', ['--exhaustive'])
run_jku_case()
run_cookie_and_header_smoke()
run_post_regression()
print(json.dumps(OUT, indent=2))
