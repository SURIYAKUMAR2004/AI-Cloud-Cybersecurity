import csv
import random
from datetime import datetime, timedelta

users = ["admin", "alice", "bob", "charlie"]
actions = [
    "Login",
    "GetObject",
    "PutObject",
    "DeleteObject",
    "CreateUser",
    "ChangePassword",
    "AssumeRole"
]

resources = [
    "EC2-Server-01",
    "S3-Bucket-01",
    "S3-Bucket-02",
    "IAM-Policy-01"
]

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
]

suspicious_ips = [
    "185.220.101.5",
    "45.155.205.10",
    "103.27.186.20"
]

rows = []

start_time = datetime.now() - timedelta(hours=24)

for i in range(500):

    timestamp = start_time + timedelta(minutes=i * 3)

    user = random.choice(users)
    action = random.choice(actions)
    resource = random.choice(resources)

    # Mostly normal activity
    if random.random() < 0.90:
        source_ip = random.choice(normal_ips)
        status = "Success"
        bytes_transferred = random.randint(100, 5000)

    # Simulated suspicious activity
    else:
        source_ip = random.choice(suspicious_ips)
        status = random.choice(["Failed", "Success"])
        bytes_transferred = random.randint(50000, 500000)

    rows.append([
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        user,
        source_ip,
        action,
        resource,
        status,
        bytes_transferred
    ])


with open("data/sample_logs.csv", "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "user",
        "source_ip",
        "action",
        "resource",
        "status",
        "bytes_transferred"
    ])

    writer.writerows(rows)

print("500 cloud security events generated successfully.")