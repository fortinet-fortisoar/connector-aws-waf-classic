"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations

logger = get_logger('aws-waf-classic')


class AwsWAFClassic(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('In execute() Operation:[{}]'.format(operation))
            action = operations.get(operation)
            return action(config, params)
        except Exception as e:
            logger.exception("An exception occurred {}".format(e))
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            return operations.get("check_health")(config)
        except Exception as e:
            logger.exception("An exception occurred in check_health {}".format(e))
            raise ConnectorError(e)
