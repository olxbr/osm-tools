import os
import json
import socket
import logging
import boto3
from datetime import datetime, date

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')
KEYPAIRS_SUMMARY_TABLE = os.getenv('KEYPAIRS_TABLE', 'osm_ec2_keypairs_summary')


def serialize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError ("Type %s not serializable" % type(obj))


def find_instance(credentials, params):
    ip = params.get('ip')
    ip_type = params.get('ipType', 'public')

    ec2_cli = boto3.client('ec2', **credentials)

    if ip is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing ip parameter'
            })
        }

    filters = {
        'Name': 'ip-address',
        'Values': [ip]
    }

    if ip_type == 'private':
        filters['Name'] = 'private-ip-address'

    instances = []

    try:
        response = ec2_cli.describe_instances(Filters=[filters])
        reservations = response['Reservations']
        if len(reservations) > 0:
            instances = reservations[0]['Instances']
    except Exception as err:
        log.error(f'Find by IP error: {err}')

    return {
        'statusCode': 200,
        'body': json.dumps({
            'instances': instances
        }, default=serialize)
    }


def check_for_elb(ip, elb_cli):
    response = elb_cli.describe_load_balancers(PageSize=100)
    marker = response.get('NextMarker')

    for lb in response['LoadBalancerDescriptions']:
        ips = socket.gethostbyname_ex(lb.get('DNSName'))[-1]
        if ip in ips:
            return lb, ips

    while marker is not None:
        response = elb_cli.describe_load_balancers(
            Marker=marker, PageSize=100)
        marker = response.get('NextMarker')

        for lb in response['LoadBalancerDescriptions']:
            ips = socket.gethostbyname_ex(lb.get('DNSName'))[-1]
            if ip in ips:
                return lb, ips

    return None, []


def check_for_elbv2(ip, elbv2_cli):
    response = elbv2_cli.describe_load_balancers(PageSize=100)
    marker = response.get('NextMarker')

    for lb in response['LoadBalancers']:
        ips = socket.gethostbyname_ex(lb.get('DNSName'))[-1]
        if ip in ips:
            return lb, ips

    while marker is not None:
        response = elbv2_cli.describe_load_balancers(
            Marker=marker, PageSize=100)
        marker = response.get('NextMarker')

        for lb in response['LoadBalancers']:
            ips = socket.gethostbyname_ex(lb.get('DNSName'))[-1]
            if ip in ips:
                return lb, ips

    return None, []


def find_elb(credentials, params):
    ip = params.get('ip')

    if ip is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing ip parameter'
            })
        }

    elb_cli = boto3.client('elb', **credentials)
    lb, ips = check_for_elb(ip, elb_cli)

    if lb:
        return {
            'statusCode': 200,
            'body': json.dumps({
                'instances': [{
                    'dns': lb.get('DNSName'),
                    'name': lb.get('LoadBalancerName'),
                    'ips': ips,
                    'type': 'classic'
                }]
            })
        }

    elbv2_cli = boto3.client('elbv2', **credentials)
    lbv2, ips = check_for_elbv2(ip, elbv2_cli)

    if lbv2:
        return {
            'statusCode': 200,
            'body': json.dumps({
                'instances': [{
                    'dns': lbv2.get('DNSName'),
                    'name': lbv2.get('LoadBalancerName'),
                    'ips': ips,
                    'type': lbv2.get('Type')
                }]
            })
        }

    return {
        'statusCode': 404,
        'body': json.dumps({
            'instances': []
        })
    }


def keypair_audit(params):
    summary_table = boto3.resource('dynamodb').Table(KEYPAIRS_SUMMARY_TABLE)
    try:
        result = summary_table.scan()
        return {
            'statusCode': 200,
            'body': json.dumps({
                'data': result.get('Items', []),
                'total': result.get('Count')
            }, default=serialize)
        }
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'data': [],
            'total': 0
        })
    }


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    account = params.get('account')
    fn = params.get('fn')

    if not account:
        if fn == 'keypair-audit':
            return keypair_audit(params)

        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing account parameter'
            })
        }

    sts_client = boto3.client('sts')
    assumed_role_obj = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account}:role/{TRUST_ROLE_NAME}',
        RoleSessionName='org_osm_role_session'
    )

    credentials = assumed_role_obj['Credentials']
    credentials = {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken'],
        'region_name': DEFAULT_REGION
    }

    if fn == 'find-instance':
        return find_instance(credentials, params)
    if fn == 'find-elb':
        return find_elb(credentials, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 'ec2tools fn not found'
        })
    }


if __name__ == '__main__':
    lambda_handler({}, {})
