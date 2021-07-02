from __future__ import print_function
import json
import ast 
import os
import sys, warnings
import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint

import boto3
from botocore.exceptions import ClientError

# Version
api_version = 'v1'

def get_secret(key, region_name = 'us-east-1'):
    secret_name = key
    region_name = region_name

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        return get_secret_value_response['SecretString']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']


def lambda_handler(event, context):
    
    print("Event : ",event)
    ApiSecretKey = os.environ['APIKEY']
    regionName = os.environ['SECRETMANAGER_REGION_NAME']
        
    print("APISecretKey used : ",ApiSecretKey)

    # Setup
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    configuration = deepsecurity.Configuration()
    configuration.host = 'https://cloudone.trendmicro.com/api'

    # Authentication
    configuration.api_key['api-secret-key'] = get_secret(key = ApiSecretKey,region_name = regionName)


    # Initialization
    # Set Any Required Values
    ComputersApi = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))

    expand_options = deepsecurity.Expand()
    expand_options.add(expand_options.none)
    expand = expand_options.list()
    overrides = False

    #MainLogic
    try:

        api_response = ComputersApi.search_computers(api_version, search_filter=deepsecurity.SearchFilter(), expand=expand, overrides=overrides)
        pprint(api_response)

    except ApiException as e:
        print("An exception occurred when calling API : %s\n" % e)

    return {
        'statusCode': 200,
        'body': json.dumps('Response !')
    }



    