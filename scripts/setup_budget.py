#!/usr/bin/env python3
"""
Sets up a $1.00 monthly AWS Budget alert on the AWS Free Tier account.
Notifies the account administrator when forecasted or actual spend exceeds $1.00.
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


def setup_one_dollar_budget(email: str = "alerts@gatekeep.security", region: str = "us-east-1"):
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    print(f"Configuring AWS $1.00 Budget Alert for AWS Account: {account_id}")

    budgets_client = boto3.client("budgets", region_name=region)

    budget_name = "GateKeep-Zero-Dollar-Free-Tier-Alert"
    budget_payload = {
        "BudgetName": budget_name,
        "BudgetLimit": {
            "Amount": "1.0",
            "Unit": "USD",
        },
        "CostFilters": {},
        "CostTypes": {
            "IncludeTax": True,
            "IncludeSubscription": True,
            "UseBlended": False,
            "IncludeRefund": False,
            "IncludeCredit": False,
            "IncludeUpfront": True,
            "IncludeRecurring": True,
            "IncludeOtherSubscription": True,
            "IncludeSupport": True,
            "IncludeDiscount": True,
            "UseAmortized": False,
        },
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST",
    }

    notifications = [
        {
            "Notification": {
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": 80.0,  # Alert at $0.80
                "ThresholdType": "PERCENTAGE",
            },
            "Subscribers": [
                {
                    "SubscriptionType": "EMAIL",
                    "Address": email,
                }
            ],
        },
        {
            "Notification": {
                "NotificationType": "FORECASTED",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": 100.0,  # Alert if forecasted to exceed $1.00
                "ThresholdType": "PERCENTAGE",
            },
            "Subscribers": [
                {
                    "SubscriptionType": "EMAIL",
                    "Address": email,
                }
            ],
        },
    ]

    try:
        # Check if budget exists
        try:
            budgets_client.describe_budget(AccountId=account_id, BudgetName=budget_name)
            print(f"Budget '{budget_name}' already exists.")
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

        budgets_client.create_budget(
            AccountId=account_id,
            Budget=budget_payload,
            NotificationsWithSubscribers=notifications,
        )
        print(f"SUCCESS: Created $1.00 AWS Budget Alert '{budget_name}' notifying {email}.")
        return True
    except ClientError as e:
        print(f"Notice: Budget configuration returned: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create $1.00 AWS Budget Alert")
    parser.add_argument("--email", default="aveec@gatekeep.security", help="Email address for budget alerts")
    args = parser.parse_args()
    setup_one_dollar_budget(email=args.email)
