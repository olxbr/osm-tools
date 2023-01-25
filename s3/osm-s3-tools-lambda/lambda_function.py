import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, date

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')
S3_BUCKETS_TABLE = os.getenv('S3_BUCKETS_TABLE', 'osm_s3_account_buckets')
S3_SUMMARY_TABLE = os.getenv('S3_SUMMARY_TABLE', 'osm_s3_bucket_summary')


def serialize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError ("Type %s not serializable" % type(obj))


def get_bucket(name, bucket_list):
    for b in bucket_list:
        if b["Name"] == name:
            return b
    return None


def bucket_status(s3_client, bucket_name):
    try:
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']['IsPublic']
    except:
        policy_status = None

    try:
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
    except:
        public_access_block = None

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
    bucket = get_bucket(bucket_name, response.get('Buckets', []))
    info = {
        'name': bucket_name,
        'policy': '',
        'tags': []
    }

    if bucket:
        info['creation_date'] = bucket['CreationDate'].isoformat()
        info['public_status'] = bucket_status(s3_client, bucket_name)

        try:
            info['policy'] = s3_client.get_bucket_policy(Bucket=bucket_name).get('Policy', '')
        except Exception as err:
            log.error(err)

        try:
            info['tags'] = s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
        except Exception as err:
            log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'bucket': info
        })
    }


def list_buckets(s3_client, params):
    account = params.get('account')

    mode = params.get('mode')
    if mode is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing mode parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(S3_BUCKETS_TABLE)

    if mode == 'latest':
        try:
            result = dynamo_table.get_item(Key={'account': account}).get("Item")
            if result:
                buckets = json.loads(result.get('buckets'))
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'account': account,
                        'updatedAt': result.get('updated_at'),
                        'buckets': buckets,
                        'total': len(buckets)
                    })
                }
        except Exception as err:
            log.error(err)

    response = s3_client.list_buckets()
    buckets = []

    for bucket in response.get("Buckets", []):
        buckets.append({
            'name': bucket["Name"],
            'creation_date': bucket["CreationDate"].isoformat()
        })

    updated_at = datetime.utcnow().astimezone().isoformat()

    try:
        result = dynamo_table.put_item(
            Item={
                'account': account,
                'updated_at': updated_at,
                'buckets': json.dumps(buckets),
                'total': len(buckets)
            }
        )
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'account': account,
            'updatedAt': updated_at,
            'buckets': buckets,
            'total': len(buckets)
        })
    }


def list_buckets_summary(params):
    account = params.get('account')
    dynamo_table = boto3.resource('dynamodb').Table(S3_SUMMARY_TABLE)

    try:
        result = dynamo_table.query(
            IndexName='account-index',
            KeyConditionExpression=Key('account').eq(account))
        if result:
            return {
                'statusCode': 200,
                'body': json.dumps(result.get("Items"))
            }
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 404,
        'body': ''
    }


def get_bucket_summary(params):
    bucket_name = params.get('bucketName')
    if bucket_name is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing bucketName parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(S3_SUMMARY_TABLE)

    try:
        result = dynamo_table.get_item(Key={'bucket': bucket_name}).get("Item")
        if result:
            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 404,
        'body': ''
    }


def put_bucket_summary(params, body):
    account = params.get('account')

    if body is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing body'
            })
        }

    body = json.loads(body)
    bucket_name = body.get('bucketName')
    compliance = body.get('compliance')
    notes = body.get('notes', '')

    if bucket_name is None or compliance is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing parameters (bucketName, compliance)'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(S3_SUMMARY_TABLE)

    try:
        _ = dynamo_table.update_item(
            Key={"bucket": bucket_name},
            UpdateExpression="set account=:a, compliance=:c, notes=:n, updated_at=:u",
            ExpressionAttributeValues={
                ":a": account,
                ":c": compliance,
                ":n": notes,
                ":u": datetime.utcnow().astimezone().isoformat()
            },
            ReturnValues="UPDATED_NEW"
        )
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'success'})
        }
    except Exception as err:
        msg = f'put_bucket_summary error: {err}'
        log.error(msg)
        return {
            'statusCode': 500,
            'body': json.dumps({'message': msg})
        }


def get_compliance_data():
    buckets_table = boto3.resource('dynamodb').Table(S3_BUCKETS_TABLE)
    summary_table = boto3.resource('dynamodb').Table(S3_SUMMARY_TABLE)

    result = {
        'inCompliance': 0,
        'notInCompliance': 0,
        'withoutReview': 0,
        'total': 0
    }

    try:
        items = buckets_table.scan(AttributesToGet=['total']).get('Items', [])
        for i in items:
            result['total'] += int(i['total'])
    except Exception as err:
        log.error(err)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'error getting total buckets'
            })
        }

    try:
        yes = summary_table.scan(Select='COUNT',
            FilterExpression=Attr('compliance').eq('yes'))
        result['inCompliance'] = yes.get('Count')

        no = summary_table.scan(Select='COUNT',
            FilterExpression=Attr('compliance').eq('no'))
        result['notInCompliance'] = no.get('Count')
    except Exception as err:
        log.error(err)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'error getting compliance data'
            })
        }


    result['withoutReview'] = (
        result['total'] - (result['inCompliance'] + result['notInCompliance'])
    )

    return {
        'statusCode': 200,
        'body': json.dumps(result)
    }


def lambda_handler(event, context):
    http_method = event['requestContext']['http']['method']
    params = event.get('queryStringParameters')
    body = event.get('body')
    account = params.get('account')
    fn = params.get('fn')

    if not account:
        if fn == 'get-compliance-data':
            return get_compliance_data()

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

    if fn == 'find-bucket':
        return find_bucket(s3_client, params)
    elif fn == 'bucket-info':
        return bucket_info(s3_client, params)
    elif fn == 'list-buckets':
        return list_buckets(s3_client, params)
    elif fn == 'list-buckets-summary':
        return list_buckets_summary(params)
    elif fn == 'get-bucket-summary':
        return get_bucket_summary(params)

    if http_method == 'PUT':
        if fn == 'put-bucket-summary':
            return put_bucket_summary(params, body)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 's3tools fn not found'
        })
    }
