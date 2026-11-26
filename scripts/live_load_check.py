"""Bounded concurrent checks against real providers and production storage.

Uses isolated accounts/workspaces and the cleanup from live_e2e. Provider keys
are read from process environment. This measures modest concurrency, not capacity.
"""

import argparse
import json
import math
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
from live_e2e import LiveSuite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='default')
    for name in ('region', 'pool', 'table', 'api', 'nvidia-url', 'nvidia-model', 'gemini-url', 'gemini-model', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--nvidia-key-env', default='GATEKEEP_TEST_NVIDIA_KEY')
    parser.add_argument('--gemini-key-env', default='GATEKEEP_TEST_GEMINI_KEY')
    args = parser.parse_args()
    suite = LiveSuite(args)
    measurements = []
    try:
        owner = suite.account('load')
        for name, url, model, key_env in [
            ('nvidia', args.nvidia_url, args.nvidia_model, args.nvidia_key_env),
            ('gemini', args.gemini_url, args.gemini_model, args.gemini_key_env),
        ]:
            ws = suite.request('POST', '/api/workspaces', owner['token'], expected=201,
                json={'name': suite.run_id + '-load-' + name}).json()['id']
            suite.workspaces.append({'id': ws, 'owner': owner['id']})
            suite.policy(owner, ws, upstream_base_url=url, upstream_api_key=os.environ[key_env],
                         mode='REDACT', inspect_responses=True, block_injections=True, rate_limit_rpm=60)
            key = suite.request('POST', f'/api/workspaces/{ws}/keys', owner['token'], expected=201,
                                json={'name': 'Temporary load test'}).json()['api_key']
            suite.hidden.append(key)
            with httpx.Client(timeout=90, limits=httpx.Limits(max_connections=12)) as client:
                def request(_):
                    start = time.perf_counter()
                    response = client.post(args.api.rstrip('/') + '/v1/chat/completions',
                        headers={'Authorization': 'Bearer ' + key}, json={'model': model,
                        'messages': [{'role': 'user', 'content': 'Reply with exactly READY.'}],
                        'max_tokens': 32, 'temperature': 0})
                    elapsed = (time.perf_counter() - start) * 1000
                    data = response.json()
                    if response.status_code != 200:
                        detail = json.dumps(data)
                        for secret in suite.hidden:
                            detail = detail.replace(secret, '[hidden]')
                        return {'elapsed_ms': elapsed, 'status': response.status_code, 'error': detail[:450]}
                    assert data['choices'][0]['message'].get('content'), 'Empty model response'
                    return {'elapsed_ms': elapsed, 'status': response.status_code,
                            'inspection_ms': data['aegisgate_meta']['inspection_ms']}
                for concurrency in (1, 5, 10):
                    start = time.perf_counter()
                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        values = list(pool.map(request, range(concurrency)))
                    wall = time.perf_counter() - start
                    latencies = sorted(value['elapsed_ms'] for value in values)
                    failures = [value for value in values if value['status'] != 200]
                    row = {'provider': name, 'concurrency': concurrency, 'requests': len(values),
                           'http_errors': len(failures), 'errors': failures,
                           'p50_ms': round(latencies[len(values)//2], 2),
                           'p95_ms': round(latencies[math.ceil(len(values)*0.95)-1], 2),
                           'max_ms': round(max(latencies), 2), 'requests_per_second': round(len(values)/wall, 2),
                           'max_inspection_ms': max((value.get('inspection_ms', 0) for value in values), default=0)}
                    measurements.append(row)
                    print(json.dumps(row), flush=True)
            logs = suite.logs(owner, ws)
            assert len(logs) == 16, 'Missing concurrent audit entries'
            print(json.dumps({'provider': name, 'durable_audit_entries': len(logs),
                'error_audits': [{'reason': log['block_reason'], 'upstream_ms': log['upstream_ms']}
                                 for log in logs if log['action'] == 'ERROR']}), flush=True)
    finally:
        cleanup = suite.cleanup()
        print(json.dumps({'cleanup': cleanup}), flush=True)
    Path(args.output).write_text(json.dumps({'measurements': measurements, 'cleanup': cleanup}, indent=2))
    return 1 if any(row['http_errors'] for row in measurements) else 0


if __name__ == '__main__':
    raise SystemExit(main())
