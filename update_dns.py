#!/usr/bin/env python3

from urllib.request import urlopen, Request

import argparse
import base64
import boto3
import json
import time


def get_ips(ip, username, password):
    url = 'http://{}/JNAP/'.format(ip)
    token = base64.b64encode('{}:{}'.format(username, password).encode('ascii')).decode('ascii')
    headers = {
        'X-JNAP-Action': 'http://linksys.com/jnap/router/GetWANStatus2',
        'X-JNAP-Authorization': 'Basic {}'.format(token),
    }
    req = Request(url, data=b'{}', headers=headers, method='POST')

    with urlopen(req) as f:
        res = json.loads(f.read().decode('utf-8'))
        ipv4_addr = None
        if res['output']['wanStatus'] == 'Connected':
            ipv4_addr = res['output']['wanConnection']['ipAddress']
        else:
            raise Exception('Missing ipv4 wan connection')
        return ipv4_addr


def update_ips(hostname, region='us-east-1', zone_id=None, ipv4=None, **kwargs):
    if ipv4 == None:
        raise TypeError('Missing ipv4 address')
    client = boto3.client('route53', **kwargs)
    changes = [
        {
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': hostname,
                'Type': 'A',
                'TTL': 300,
                'ResourceRecords': [{'Value': ipv4}],
            },
        },
    ]
    response = client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={'Changes': changes})
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise(Exception('Update failed {}'.format(json.dumps(response))))


def main(hostname, router_ip='192.168.1.1', router_username='admin', router_password='password', **kwargs):
    previpv4 = None
    succeeded = False
    while True:
        try:
            print('{} Checking IP addresses'.format(
                time.strftime('{%Y-%m-%dT%H:%M:%S}')))
            ipv4 = get_ip(router_ip, router_username, router_password)
            if ipv4 == previpv4 and succeeded == True:
                print('{} Nothing changed since last update. Skipping...'.format(
                    time.strftime('{%Y-%m-%dT%H:%M:%S}')))
                continue
            print('{} Updating DNS entries'.format(
                time.strftime('{%Y-%m-%dT%H:%M:%S}')))
            update_ips(hostname, ipv4=ipv4, **kwargs)
            print('{} Updated {} to A {}'.format(
                time.strftime('{%Y-%m-%dT%H:%M:%S}'), hostname, ipv4))
            succeeded = True
            previpv4 = ipv4
        except Exception as e:
            succeeded = False
            print('{} Update failed for {} to A {} and AAAA {}:'.format(
                time.strftime('{%Y-%m-%dT%H:%M:%S}'), hostname, ipv4))
            print(e)
        finally:
            time.sleep(3600)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Route 53 dynamic DNS updater')
    parser.add_argument('--host', required=True, help='The hostname to update')
    parser.add_argument('--router-ip', default='192.168.1.1',
                        help='The router IP address')
    parser.add_argument('--router-user', default='admin',
                        help='The router username')
    parser.add_argument('--router-password',
                        default='password', help='The router password')
    parser.add_argument('--hosted-zone-id', required=True,
                        help='The Route 53 Hosted Zone ID')
    parser.add_argument('--region', default='us-east-1', help='The AWS Region')
    parser.add_argument('--aws-access-key-id', required=True,
                        help='The AWS Access Key ID')
    parser.add_argument('--aws-secret-access-key',
                        required=True, help='The AWS Secret Access Key')
    args = parser.parse_args()
    print('Starting DNS updater')
    main(args.host, router_ip=args.router_ip, router_username=args.router_user, router_password=args.router_password, zone_id=args.hosted_zone_id,
         region=args.region, aws_access_key_id=args.aws_access_key_id, aws_secret_access_key=args.aws_secret_access_key)
