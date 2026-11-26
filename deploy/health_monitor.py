"""Publish service, disk and memory health from EC2 using its instance role."""

import json
import os
import shutil
import urllib.request

import boto3


def main():
    healthy = 0
    try:
        for url in ("http://127.0.0.1:8000/health?check_db=true", os.environ["GATEKEEP_PUBLIC_HEALTH_URL"]):
            with urllib.request.urlopen(url, timeout=10) as response:
                result = json.load(response)
            if result.get("status") != "healthy" or result.get("database") != "connected":
                raise ValueError("Service/database unhealthy")
        healthy = 1
    except Exception:
        pass
    disk = shutil.disk_usage("/opt/aegisgate")
    with open("/proc/meminfo", encoding="utf-8") as source:
        memory = {line.split(":")[0]: int(line.split()[1]) for line in source}
    dimensions = [{"Name": "InstanceId", "Value": os.environ["GATEKEEP_INSTANCE_ID"]}]
    metrics = [
        {"MetricName": "ServiceHealthy", "Value": healthy, "Unit": "Count"},
        {"MetricName": "DiskUsedPercent", "Value": 100 * disk.used / disk.total, "Unit": "Percent"},
        {"MetricName": "MemoryUsedPercent", "Value": 100 * (1 - memory["MemAvailable"] / memory["MemTotal"]), "Unit": "Percent"},
    ]
    for metric in metrics:
        metric["Dimensions"] = dimensions
    boto3.client("cloudwatch", region_name=os.environ["AWS_REGION"]).put_metric_data(
        Namespace="GateKeep", MetricData=metrics
    )
    print(json.dumps({metric["MetricName"]: metric["Value"] for metric in metrics}))


if __name__ == "__main__":
    main()
