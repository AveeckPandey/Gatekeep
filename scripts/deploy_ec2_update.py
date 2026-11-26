"""Deploy backend Python files through SSM with checksums and health-based rollback.

Uses the selected AWS profile; never packages .env files or provider credentials.
"""

import argparse
import base64
import hashlib
import json
import time
import zlib
from pathlib import Path

import boto3

INSTALLER = r'''
import base64, hashlib, json, os, pathlib, shutil, subprocess, time, urllib.request, zlib
root = pathlib.Path('/opt/aegisgate').resolve()
assert root.is_dir()
payload = json.loads(zlib.decompress(base64.b64decode(PAYLOAD)))
backup = root / '.gatekeep-backups' / payload['release']
backup.mkdir(parents=True, mode=0o700, exist_ok=False)
os.chmod(backup.parent, 0o700)
targets = []
for name, entry in payload['files'].items():
    path = (root / name).resolve()
    if not path.is_relative_to(root / 'app') or path.suffix != '.py':
        raise RuntimeError('Invalid deployment target')
    contents = base64.b64decode(entry['data'])
    if hashlib.sha256(contents).hexdigest() != entry['sha256']:
        raise RuntimeError('Checksum mismatch')
    compile(contents, name, 'exec')
    original = backup / name
    if path.exists():
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, original)
    targets.append((path, original, contents))
(backup / 'manifest.json').write_text(json.dumps({
    'files': list(payload['files']), 'release': payload['release']
}))
def health():
    for _ in range(20):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8000/health?check_db=true', timeout=5) as response:
                body = json.load(response)
            if body.get('status') == 'healthy' and body.get('database') == 'connected':
                return body
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError('Backend/database health check failed')
subprocess.run(['systemctl', 'stop', 'aegisgate'], check=True)
try:
    for path, original, contents in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        os.chmod(path, 0o640)
        shutil.chown(path, user='aegisgate', group='aegisgate')
    subprocess.run(['systemctl', 'start', 'aegisgate'], check=True)
    status = health()
    manifest = {'release': payload['release'], 'files': {
        name: entry['sha256'] for name, entry in payload['files'].items()
    }}
    for name, digest in manifest['files'].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('Installed checksum mismatch')
    (root / 'deployment.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({'deployed': True, 'release': payload['release'],
                      'backup': str(backup), 'files_verified': len(targets), 'health': status}))
except Exception:
    subprocess.run(['systemctl', 'stop', 'aegisgate'], check=False)
    for path, original, contents in targets:
        if original.exists():
            shutil.copy2(original, path)
            shutil.chown(path, user='aegisgate', group='aegisgate')
        elif path.exists():
            path.unlink()
    subprocess.run(['systemctl', 'start', 'aegisgate'], check=True)
    print(json.dumps({'deployed': False, 'rolled_back': True, 'health': health()}))
    raise
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='default')
    parser.add_argument('--region', required=True)
    parser.add_argument('--instance-id', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    instance = session.client('ec2').describe_instances(InstanceIds=[args.instance_id])['Reservations'][0]['Instances'][0]
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    if tags.get('Project') != 'GateKeep' or instance['State']['Name'] != 'running':
        raise RuntimeError('Target must be a running instance tagged Project=GateKeep')
    files = {}
    for path in sorted((root / 'app').rglob('*.py')):
        contents = path.read_text(encoding='utf-8').replace('\r\n', '\n').encode()
        name = path.relative_to(root).as_posix()
        compile(contents, name, 'exec')
        files[name] = {'data': base64.b64encode(contents).decode(),
                       'sha256': hashlib.sha256(contents).hexdigest()}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:12]
    release = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + digest
    payload = base64.b64encode(zlib.compress(json.dumps({'release': release, 'files': files}).encode(), 9)).decode()
    script = "PAYLOAD = " + repr(payload) + '\n' + INSTALLER
    command = "/opt/aegisgate/venv/bin/python - <<'GATEKEEP_DEPLOY'\n" + script + '\nGATEKEEP_DEPLOY'
    ssm = session.client('ssm')
    sent = ssm.send_command(InstanceIds=[args.instance_id], DocumentName='AWS-RunShellScript',
        Parameters={'commands': [command], 'executionTimeout': ['180']},
        Comment='Deploy tested GateKeep backend fixes with backup and automatic health rollback')
    command_id = sent['Command']['CommandId']
    print(json.dumps({'command_id': command_id, 'release': release, 'files': len(files)}), flush=True)
    for _ in range(90):
        time.sleep(2)
        try:
            result = ssm.get_command_invocation(CommandId=command_id, InstanceId=args.instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if result['Status'] in ('Pending', 'InProgress', 'Delayed'):
            continue
        print(result.get('StandardOutputContent', ''), flush=True)
        if result['Status'] != 'Success':
            print(result.get('StandardErrorContent', ''), flush=True)
            raise RuntimeError('SSM deployment status: ' + result['Status'])
        return
    raise RuntimeError('Timed out waiting for SSM; inspect command ' + command_id)


if __name__ == '__main__':
    main()
