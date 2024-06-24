"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
import requests

from boto3 import client
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('aws-waf-classic')
TEMP_CRED_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{aws_iam_role}'

MAPPING = {
    "AWS WAF Classic": "waf",
    "AWS WAF Classic Regional": "waf-regional"
}


def _get_credentials_from_config(config):
    aws_access_key = _get_input(config, "access_key", str)
    aws_region = _get_input(config, "aws_region", str)
    aws_secret_access_key = _get_input(config, "secret_key", str)
    aws_service_name = _get_input(config, "service_name", str)
    verify_ssl = _get_input(config, "verify_ssl", bool)
    return aws_access_key, aws_region, aws_secret_access_key, aws_service_name, verify_ssl


def _get_temp_credentials(config):
    try:
        aws_iam_role = _get_input(config, "aws_iam_role", str)
        url = TEMP_CRED_ENDPOINT.format(aws_iam_role=aws_iam_role)
        resp = requests.get(url=url, verify=False)
        if resp.ok:
            data = json.loads(resp.text)
            return data
        else:
            raise ConnectorError("Unable to validate the credentials")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _create_client(config):
    logger.info("Creating Boto3 client")
    try:
        config_type = _get_input(config, "config_type", str)
        if config_type == "IAM Role":
            aws_region = _get_input(config, "aws_region", str)
            aws_service_name = _get_input(config, "service_name", str)
            verify_ssl = _get_input(config, "verify_ssl", bool)
            data = _get_temp_credentials(config)
            boto_client = client(MAPPING.get(aws_service_name), region_name=aws_region, aws_access_key_id=data.get('AccessKeyId'),
                                 aws_secret_access_key=data.get('SecretAccessKey'), aws_session_token=data.get('Token'),
                                 verify=verify_ssl)
        else:
            aws_access_key, aws_region, aws_secret_access_key, aws_service_name, verify_ssl = _get_credentials_from_config(config)
            boto_client = client(MAPPING.get(aws_service_name), region_name=aws_region, aws_access_key_id=aws_access_key,
                                 aws_secret_access_key=aws_secret_access_key, verify=verify_ssl)
        return boto_client
    except Exception as Err:
        raise ConnectorError(Err)


def _get_input(params, key, type):
    ret_val = params.get(key, None)
    if ret_val:
        if isinstance(ret_val, bytes):
            ret_val = ret_val.decode('utf-8')
        if isinstance(ret_val, type):
            return ret_val
        else:
            logger.info(
                "Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(
                    str(key), str(type)))
            raise ConnectorError(
                "Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(str(key),
                                                                                                             str(type)))
    else:
        if ret_val == {} or ret_val == [] or ret_val == 0:
            return ret_val
        return None


def _boto_execute(client, function, **kwargs):
    logger.info("Executing boto function {0}".format(function))
    try:
        boto_function = getattr(client, function)
    except Exception as e:
        error_msg = "Function {0} not available to client. Error Message as follows: {1}".format(function, str(e))
        logger.exception(error_msg)
        raise ConnectorError(error_msg)
    try:
        boto_response = boto_function(**kwargs)
        if boto_response is None or boto_response["ResponseMetadata"]["HTTPStatusCode"] == 200 or \
                boto_response["ResponseMetadata"]["HTTPStatusCode"] == 204:
            return boto_response
        else:
            error_msg = "Error executing function {0}. Server Response as follows: {1}".format(function, str(e))
            logger.error(error_msg)
            raise ConnectorError(error_msg)
    except Exception as e:
        error_msg = "Error executing function {0}. Error message as follows: {1}".format(function, str(e))
        logger.error(error_msg)
        raise ConnectorError(error_msg)


def check_health(config):
    try:
        available = _create_client(config)
        if available:
            return True
        else:
            logger.info('Invalid region_name or aws_access_key_id or aws_secret_access_key')
            raise ConnectorError('Invalid region_name or aws_access_key_id or aws_secret_access_key')
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def build_payload(params):
    return {k: v for k, v in params.items() if v is not None and v != ''}


def get_ip_set(config, params):
    client = _create_client(config)
    return _boto_execute(client, "get_ip_set", **params)


def list_ip_set(config, params):
    client = _create_client(config)
    params = build_payload(params)
    return _boto_execute(client, "list_ip_sets", **params)


def create_ip_set(config, params):
    client = _create_client(config)
    return _boto_execute(client, "create_ip_set", **params)


def delete_ip_set(config, params):
    client = _create_client(config)
    return _boto_execute(client, "delete_ip_set", **params)


def get_change_token(config, params):
    client = _create_client(config)
    return _boto_execute(client, "get_change_token", **params)


def update_ip_set(config, params):
    client = _create_client(config)
    return _boto_execute(client, "update_ip_set", **params)


operations = {
    'get_ip_set': get_ip_set,
    'create_ip_set': create_ip_set,
    'list_ip_set': list_ip_set,
    'delete_ip_set': delete_ip_set,
    'update_ip_set': update_ip_set,
    'get_change_token': get_change_token,
    'check_health': check_health
}
