"""Verify a real DynamoDB backup by restoring a separate temporary table.

Keeps the on-demand backup; deletes only the newly created restore-check table.
The source table is never modified. Output contains counts/checksums, not records.
"""

import argparse
import hashlib
import json
import time

import boto3


def snapshot(table):
    items = []
    page = table.scan(ConsistentRead=True)
    while True:
        items.extend(page['Items'])
        if not page.get('LastEvaluatedKey'):
            break
        page = table.scan(ConsistentRead=True, ExclusiveStartKey=page['LastEvaluatedKey'])
    serialized = json.dumps(sorted(items, key=lambda item: (item['PK'], item['SK'])), sort_keys=True, default=str)
    return len(items), hashlib.sha256(serialized.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='default')
    parser.add_argument('--region', required=True)
    parser.add_argument('--table', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    db = session.client('dynamodb')
    resource = session.resource('dynamodb')
    suffix = time.strftime('%Y%m%d%H%M%S', time.gmtime())
    target = 'gatekeep-restore-check-' + suffix
    baseline = snapshot(resource.Table(args.table))
    backup = db.create_backup(TableName=args.table, BackupName='gatekeep-release-' + suffix)['BackupDetails']['BackupArn']
    print(json.dumps({'backup': backup, 'restore_target': target}), flush=True)
    for _ in range(90):
        if db.describe_backup(BackupArn=backup)['BackupDescription']['BackupDetails']['BackupStatus'] == 'AVAILABLE':
            break
        time.sleep(2)
    db.restore_table_from_backup(TargetTableName=target, BackupArn=backup, BillingModeOverride='PAY_PER_REQUEST')
    try:
        for _ in range(120):
            details = db.describe_table(TableName=target)['Table']
            if details['TableStatus'] == 'ACTIVE':
                break
            time.sleep(5)
        else:
            raise RuntimeError('Restore table did not become active')
        restored = snapshot(resource.Table(target))
        result = {'source_table': args.table, 'backup_arn': backup, 'restored_table': target,
                  'source_items': baseline[0], 'restored_items': restored[0],
                  'contents_match': restored == baseline, 'restored_sha256': restored[1]}
        if restored != baseline:
            raise RuntimeError('Restored snapshot differs from pre-backup source; check concurrent writes')
    finally:
        # Only the exact table created above is eligible for cleanup.
        assert target.startswith('gatekeep-restore-check-') and target != args.table
        db.delete_table(TableName=target)
        db.get_waiter('table_not_exists').wait(TableName=target, WaiterConfig={'Delay': 5, 'MaxAttempts': 60})
    result['temporary_restore_table_removed'] = True
    with open(args.output, 'w', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
