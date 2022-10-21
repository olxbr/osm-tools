import os
import json
import logging
import boto3
import botocore

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')


def get_bucket(name, bucket_list):
    for b in bucket_list:
        if b["Name"] == name:
            return b
    return None


def find_bucket(s3_client, params):
    bucket_name = params.get('bucketName')
    if bucket_name is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing bucketName parameter'
            })
        }

    search_by = params.get('searchBy')
    if search_by is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing searchBy parameter'
            })
        }

    response = s3_client.list_buckets()
    bucket_list = response.get("Buckets", [])
    buckets = []

    if search_by == 'fullname':
        bucket = get_bucket(bucket_name, bucket_list)
        if bucket:
            buckets = [{
                'name': bucket["Name"],
                'creation_date': bucket["CreationDate"].isoformat()
            }]

    if search_by == 'prefix':
        for bucket in bucket_list:
            if bucket["Name"].startswith(bucket_name):
                buckets.append({
                    'name': bucket["Name"],
                    'creation_date': bucket["CreationDate"].isoformat()
                })

    return {
        'statusCode': 200,
        'body': json.dumps({
            'buckets': buckets
        })
    }


def bucket_status(policy_status, public_access_block):
    if policy_status == None and public_access_block == None: # 0
        return 'Objects can be public'

    elif policy_status == None and public_access_block != None: # public_access_block
        if not all(list(public_access_block.values())):
            return 'Objects can be public'
        if all(list(public_access_block.values())) or public_access_block['IgnorePublicAcls']:
            return 'Bucket and objects not public'

    if policy_status != None and public_access_block == None: # policy
        if policy_status:
            return 'Public'
        else:
            return 'Objects can be public'

    elif policy_status != None and public_access_block != None: # 2
        if policy_status and not all(list(public_access_block.values())):
            return 'Public'
        elif policy_status and all(list(public_access_block.values())):
            return 'Only authorized users of this account'

        if not policy_status and not all(list(public_access_block.values())):
            return 'Objects can be public'

        elif not policy_status and all(list(public_access_block.values())) or public_access_block['IgnorePublicAcls']:
            return 'Bucket and objects not public'


def bucket_info(s3_client, params):
    bucket_name = params.get('bucketName')
    if bucket_name is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing bucketName parameter'
            })
        }

    response = s3_client.list_buckets()
    bucket = get_bucket(bucket_name, response.get("Buckets", []))
    info = {'name': bucket_name}

    if bucket:
        info['creation_date'] = bucket["CreationDate"].isoformat()

        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket['Name'])['PolicyStatus']['IsPublic']
            info['is_public'] = policy_status
        except botocore.exceptions.ClientError as err:
            policy_status = None
            log.error(err)

        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket['Name'])['PublicAccessBlockConfiguration']
            info['public_access_block'] = public_access_block
        except botocore.exceptions.ClientError as err:
            public_access_block = None
            log.error(err)

        info["public_status"] = bucket_status(policy_status, public_access_block)

        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            info['policy'] = policy['Policy']
        except Exception as err:
            info["policy"] = ""
            log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'bucket': info
        })
    }


def list_buckets(s3_client, params):
    response = s3_client.list_buckets()
    buckets = response.get("Buckets", [])

    return {
        'statusCode': 200,
        'body': json.dumps({
            'account': params.get('account'),
            'buckets': buckets
        })
    }


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    if params is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing queryStringParameters'
            })
        }

    account = params.get('account')
    if account is None:
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
    s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=DEFAULT_REGION
    )

    fn = params.get('fn')
    if fn == 'find-bucket':
        return find_bucket(s3_client, params)
    elif fn == 'bucket-info':
        return bucket_info(s3_client, params)
    elif fn == 'list-buckets':
        return list_buckets(s3_client, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 's3tools fn not found'
        })
    }
