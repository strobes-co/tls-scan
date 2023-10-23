from tls_scan.main import async_main
import asyncio

import requests
import json

AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def get_ec2_cidr_ranges():
    cidrs = []
    response = requests.get(AWS_IP_RANGES_URL)
    if response.status_code != 200:
        print("Failed to fetch IP ranges from AWS.")
        return

    data = response.json()
    for prefix in data['prefixes']:
        if prefix['service'] == 'EC2':
            cidrs.append(prefix['ip_prefix'])

    return cidrs


loop = asyncio.get_event_loop()
cidrs = get_ec2_cidr_ranges()
for cidr in cidrs:
    loop.run_until_complete(async_main(cidr, 100))
loop.close()
