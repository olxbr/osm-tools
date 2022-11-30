import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime, date

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')
IAM_ROLES_TABLE = os.getenv('IAM_ROLES_TABLE', 'osm_iam_account_roles')
IAM_SUMMARY_TABLE = os.getenv('IAM_SUMMARY_TABLE', 'osm_iam_role_summary')


def serialize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError ("Type %s not serializable" % type(obj))


def list_roles(iam_client, params):
    account = params.get('account')
    mode = params.get('mode')

    if mode is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing mode parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(IAM_ROLES_TABLE)

    if mode == 'latest':
        try:
            result = dynamo_table.get_item(Key={'account': account}).get("Item")
            if result:
                roles = json.loads(result.get('roles'))
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'account': account,
                        'updatedAt': result.get('updatedAt'),
                        'roles': roles
                    })
                }
        except Exception as err:
            log.error(err)

    result = iam_client.list_roles(MaxItems=100)
    roles = result.get('Roles', [])
    marker = result.get('Marker')

    while marker is not None:
        result = iam_client.list_roles(Marker=marker, MaxItems=100)
        roles = roles + result.get('Roles', [])
        marker = result.get('Marker')

    updated_at = datetime.utcnow().astimezone().isoformat()

    try:
        result = dynamo_table.put_item(
            Item={
                'account': account,
                'updatedAt': updated_at,
                'roles': json.dumps(roles, default=serialize)
            }
        )
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'account': account,
            'updatedAt': updated_at,
            'roles': roles
        }, default=serialize)
    }


def get_role(iam_client, params):
    role_name = params.get('roleName')

    if role_name is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing roleName parameter'
            })
        }

    try:
        result = iam_client.get_role(RoleName=role_name)
        role = result.get('Role')
    except iam_client.exceptions.NoSuchEntityException:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'message': 'role not found'
            })
        }
    except Exception as err:
        msg = f'Get role fail: {err}'
        log.error(msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': msg
            })
        }

    return {
        'statusCode': 200,
        'body': json.dumps({
            'role': role
        })
    }


def lambda_handler(event, context):
    http_method = event['requestContext']['http']['method']
    params = event.get('queryStringParameters')
    body = event.get('body')

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

    iam_client = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=DEFAULT_REGION
    )

    fn = params.get('fn')

    if fn == 'list-roles':
        return list_roles(iam_client, params)
    if fn == 'get-role':
        return get_role(iam_client, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 'iamtools fn not found'
        })
    }
