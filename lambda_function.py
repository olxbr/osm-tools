import os
import json
import logging
import boto3

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')


def get_bucket(name, bucket_list):
    for b in bucket_list:
        if b["Name"] == name:
            return b
    return None


def find_bucket(s3_client, params):
    bucket_name = params.get('bucketName')
    if not bucket_name:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing bucket_name parameter'
            })
        }

    search_by = params.get('searchBy')
    if not search_by:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing search_by parameter'
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


def bucket_info(s3_client, params):
    bucket_name = params.get('bucketName')
    if not bucket_name:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing bucket_name parameter'
            })
        }

    response = s3_client.list_buckets()
    bucket = get_bucket(bucket_name, response.get("Buckets", []))
    info = {'name': bucket_name}

    if bucket:
        info['creation_date'] = bucket["CreationDate"].isoformat()

        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            info["is_public"] = policy_status['PolicyStatus']['IsPublic']
        except Exception as err:
            info["is_public"] = ""
            log.error(err)

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


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    if not params:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing queryStringParameters'
            })
        }

    account = params.get('account')
    if not account:
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
        region_name=AWS_REGION
    )

    fn = params.get('fn')
    if fn == 'find-bucket':
        return find_bucket(s3_client, params)
    elif fn == 'bucket-info':
        return bucket_info(s3_client, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 's3tools fn not found'
        })
    }
