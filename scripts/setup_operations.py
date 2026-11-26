"""Configure GateKeep recovery and alarms on an existing EC2 deployment."""

import argparse
import base64
import json
from pathlib import Path

import boto3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='default')
    for key in ('region', 'instance-id', 'role', 'table', 'health-url', 'email'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    session.client('dynamodb').update_continuous_backups(TableName=args.table,
        PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True, 'RecoveryPeriodInDays': 35})
    session.client('dynamodb').update_table(TableName=args.table, DeletionProtectionEnabled=True)
    sns = session.client('sns')
    topic = sns.create_topic(Name='gatekeep-production-alerts')['TopicArn']
    existing = sns.list_subscriptions_by_topic(TopicArn=topic)['Subscriptions']
    if not any(sub['Endpoint'] == args.email and sub['Protocol'] == 'email' for sub in existing):
        sns.subscribe(TopicArn=topic, Protocol='email', Endpoint=args.email)
    session.client('iam').put_role_policy(RoleName=args.role, PolicyName='GateKeepHealthMetrics',
        PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'cloudwatch:PutMetricData', 'Resource': '*',
            'Condition': {'StringEquals': {'cloudwatch:namespace': 'GateKeep'}}}]}))
    monitor = Path(__file__).resolve().parents[1] / 'deploy' / 'health_monitor.py'
    encoded = base64.b64encode(monitor.read_bytes()).decode()
    service = '\n'.join([
        '[Unit]', 'Description=GateKeep service and resource health metrics', 'After=network-online.target',
        '[Service]', 'Type=oneshot', 'User=aegisgate', 'Group=aegisgate',
        f'Environment=AWS_REGION={args.region}', f'Environment=GATEKEEP_INSTANCE_ID={args.instance_id}',
        f'Environment=GATEKEEP_PUBLIC_HEALTH_URL={args.health_url}',
        'ExecStart=/opt/aegisgate/venv/bin/python /opt/aegisgate/health_monitor.py',
        'NoNewPrivileges=true', 'ProtectSystem=strict', 'ProtectHome=true', 'PrivateTmp=true',
        'TimeoutStartSec=50', '',
    ])
    timer = '[Unit]\nDescription=Check GateKeep health every minute\n[Timer]\nOnBootSec=60\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n'
    install = f'''import base64,pathlib,subprocess
pathlib.Path('/opt/aegisgate/health_monitor.py').write_bytes(base64.b64decode({encoded!r}))
pathlib.Path('/opt/aegisgate/health_monitor.py').chmod(0o644)
pathlib.Path('/etc/systemd/system/gatekeep-health.service').write_text({service!r})
pathlib.Path('/etc/systemd/system/gatekeep-health.timer').write_text({timer!r})
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','gatekeep-health.timer'],check=True)
'''
    ssm = session.client('ssm')
    sent = ssm.send_command(InstanceIds=[args.instance_id], DocumentName='AWS-RunShellScript',
        Parameters={'commands': ["python3 - <<'GK_MONITOR'\n" + install + "\nGK_MONITOR"]},
        Comment='Install authorized GateKeep production health metric timer')
    alarms = [
        ('instance-status', 'AWS/EC2', 'StatusCheckFailed', 'Maximum', 60, 2, 1, 'GreaterThanOrEqualToThreshold', 'missing'),
        ('cpu-high', 'AWS/EC2', 'CPUUtilization', 'Average', 300, 3, 85, 'GreaterThanThreshold', 'missing'),
        ('cpu-credits-low', 'AWS/EC2', 'CPUCreditBalance', 'Average', 300, 3, 10, 'LessThanThreshold', 'missing'),
        ('service-unhealthy', 'GateKeep', 'ServiceHealthy', 'Minimum', 60, 3, 1, 'LessThanThreshold', 'breaching'),
        ('disk-high', 'GateKeep', 'DiskUsedPercent', 'Maximum', 60, 3, 85, 'GreaterThanThreshold', 'missing'),
        ('memory-high', 'GateKeep', 'MemoryUsedPercent', 'Average', 60, 5, 90, 'GreaterThanThreshold', 'missing'),
    ]
    cw = session.client('cloudwatch')
    for name, namespace, metric, statistic, period, evaluations, threshold, operator, missing in alarms:
        cw.put_metric_alarm(AlarmName='gatekeep-production-' + name,
            AlarmDescription='GateKeep production monitoring; see deploy/OPERATIONS.md for response steps.',
            Namespace=namespace, MetricName=metric, Statistic=statistic,
            Dimensions=[{'Name': 'InstanceId', 'Value': args.instance_id}], Period=period,
            EvaluationPeriods=evaluations, Threshold=threshold, ComparisonOperator=operator,
            TreatMissingData=missing, AlarmActions=[topic], OKActions=[topic])
    print(json.dumps({'point_in_time_recovery': 'enabled', 'retention_days': 35,
        'deletion_protection': True, 'alarm_count': len(alarms), 'topic': topic,
        'monitor_install_command_id': sent['Command']['CommandId']}))


if __name__ == '__main__':
    main()
