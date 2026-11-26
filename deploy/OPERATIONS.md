# Production operations

The frontend is deployed through the repository's Vercel integration. The API runs
on the existing EC2 instance behind Nginx/TLS, with Cognito authentication and
DynamoDB storage. GitHub Actions verifies both `master` and `main`; it does not
deploy the retired Lambda target.

## Deploy and roll back

Run backend tests, frontend lint/build, and review the diff before release. Push
the verified commit, then update the existing instance:

```powershell
python scripts/deploy_ec2_update.py --profile default --region us-east-1 --instance-id <instance-id>
```

The updater packages only `app/**/*.py`, verifies checksums, and stores the previous
files under `/opt/aegisgate/.gatekeep-backups/<release>`. It restarts the service
and checks service/database health. Failed health checks restore the previous
files automatically. Successful deployments record checksums in
`/opt/aegisgate/deployment.json`. Dependency changes require a separate reviewed
virtual-environment update; this source updater does not install packages.

For a later rollback, deploy a checkout of the previous verified commit using the
same updater. Keep `/etc/aegisgate/aegisgate.env` and the encrypted SSM parameter
`/gatekeep/production/env` intact. In particular, replacing the Fernet encryption
key makes stored provider credentials unreadable.

## Monitoring and alerts

`scripts/setup_operations.py` configures the existing instance and table. All IDs,
region, public health URL and alert email are explicit CLI inputs. AWS monitoring
and backup services are metered.

- The `gatekeep-health.timer` runs every minute using the instance role. It checks
  both loopback API health and public HTTPS health, including DynamoDB connectivity.
- It publishes only health, memory and disk measurements to namespace `GateKeep`.
  The role policy permits metric writes only to this namespace.
- Six CloudWatch alarms cover service health (including missing measurements),
  EC2 status checks, sustained CPU usage, low CPU credits, disk space and memory.
- Alarm and recovery notifications go through `gatekeep-production-alerts`.
  The recipient must confirm the SNS subscription before email delivery works.

For service alarms, check public `/health?check_db=true`, then use SSM to inspect
`systemctl status aegisgate`, `systemctl status nginx`, and
`journalctl -u aegisgate --since '15 minutes ago'`. Avoid copying credentials or
request bodies into incident messages. Check the health timer with
`journalctl -u gatekeep-health.service`.

For resource alarms, inspect disk/memory and CPU-credit metrics before resizing
or changing instance settings. The current single-instance deployment has no
automatic failover; monitoring does not make it highly available.

## Data recovery

DynamoDB deletion protection is enabled, with 35 days of point-in-time recovery.
Restore to a new table, validate its contents, and configure its IAM access, TTL,
PITR, alarms and deletion protection before switching the backend table setting.
AWS does not carry all operational settings over to a restored table.

Use an isolated restore drill:

```powershell
python scripts/verify_backup.py --profile default --region us-east-1 --table <production-table> --output <result-json-path>
```

This keeps an on-demand backup, restores a temporary table, compares counts and
checksums, and removes only that temporary table. Run the snapshot comparison
during a quiet period because source writes around backup creation can cause a
comparison mismatch. It never switches the application to the restored table.

## Authentication checks

Signup uses Cognito email confirmation. Password recovery is available at
`/forgot-password`, calling `/api/auth/forgot-password` and
`/api/auth/reset-password`. The reset request uses a generic response regardless
of account existence. Codes and new passwords are verified by Cognito; the app
does not store reset codes or passwords. Test email delivery with an inbox you
control and a separate account, then remove only that test account.

## Live checks and concurrency

`scripts/live_e2e.py` uses actual Cognito, DynamoDB and provider requests. It checks
authentication, workspace isolation, hashed/encrypted key storage, completions,
streaming, tool calls, request/response redaction, blocking, provider failures,
audit entries and key revocation. Temporary accounts and workspaces are removed.
Supply provider keys through process environment variables, never Git files.

`scripts/live_load_check.py` sends 1, 5 and 10 concurrent short completions for
each configured provider, verifies persisted audit entries, and removes its test
resources. This is a bounded smoke test, not a sustained capacity or SLA claim.
Run `--help` on either script for required deployment/provider arguments.
