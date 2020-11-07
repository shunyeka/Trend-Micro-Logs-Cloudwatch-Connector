import os
import sys
import json
import random
import string
import datetime
import tempfile
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
from list_vulnerabilities import *

# Read all the environment variables
DSSC_URL = os.environ['DSSC_URL']
DSSC_SMARTCHECK_USER = os.environ['DSSC_SMARTCHECK_USER']
DSSC_SMARTCHECK_PASSWORD = os.environ['DSSC_SMARTCHECK_PASSWORD']
DSSC_MIN_SEVERITY = os.environ['DSSC_MIN_SEVERITY']
DSSC_SHOW_FIXED = os.environ['DSSC_SHOW_FIXED']
DSSC_SHOW_OVERRIDDEN = os.environ['DSSC_SHOW_OVERRIDDEN']
DSSC_INSECURE_SKIP_TLS_VERIFY = os.environ['DSSC_INSECURE_SKIP_TLS_VERIFY']


def lambda_handler(event, context):
    if 'body' in event:
        jsonBody = json.loads(event['body'])
    else:
        jsonBody = event
    if 'scan' in jsonBody:
        """
        Parse the incoming scaned data
        """
        scan = jsonBody['scan']

        if 'findings' not in jsonBody['scan']:
            return {
                'statusCode': 200,
                'body': 'Scan not have any findings'
            }

        dssc_results = get_analysis(DSSC_URL, DSSC_SMARTCHECK_USER, DSSC_SMARTCHECK_PASSWORD, scan["name"],
                                    DSSC_MIN_SEVERITY, DSSC_SHOW_FIXED, DSSC_SHOW_OVERRIDDEN,
                                    DSSC_INSECURE_SKIP_TLS_VERIFY)

        if not dssc_results:
            return {
                'statusCode': 200,
                'body': 'Scan not have any venerability'
            }
        else:
            logger.info('#####')
            logger.info(dssc_results)
            logger.info('#####')
    else:
        parse_sns_notification(jsonBody)

    return {
        'statusCode': 200,
        'body': 'ok'
    }


def parse_sns_notification(jsonBody):
    """
    Parse the incoming SNS notification for a Deep Security event
    """
    timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    # print(jsonBody)

    if type(jsonBody) == type({}):
        if 'Records' in jsonBody:
            print("Processing {} records".format(len(jsonBody['Records'])))
            for i, record in enumerate(jsonBody['Records']):
                print("Record {}/{}".format(i, len(jsonBody['Records'])))

                if 'Sns' in record:
                    timestamp = datetime.datetime.now()
                    time_received = record['Sns']['Timestamp'] if 'Timestamp' in record['Sns'] else None
                    if time_received:
                        try:
                            timestamp = datetime.datetime.strptime(time_received, timestamp_format)
                        except:
                            pass  # we can silently fail and try to catch later

                    if 'Message' in record['Sns']:
                        record_docs = json.loads(record['Sns']['Message'])

                        # some versions of this feature send single events instead of an array
                        if type(record_docs) == type({}): record_docs = [record_docs]

                        for record_doc in record_docs:
                            if 'LogDate' in record_doc:
                                # LogDate is the actually timestamp of the event. We need a timestamp for the
                                # event and the order of preference is:
                                #    1. LogDate
                                #    2. Time received by Amazon SNS
                                #    3. Time processed by AWS Lambda
                                #
                                # When both LogDate and time received by Amazon SNS are present, we'll also
                                # calculate the delivery delay and record that with the event as 'DeliveryDelay'
                                time_generated = record_doc['LogDate']
                                try:
                                    tg = datetime.datetime.strptime(time_generated, timestamp_format)
                                    timestamp = tg  # update the timestamp to the actual event time instead of the time is was received
                                    tr = datetime.datetime.strptime(time_received, timestamp_format)
                                    d = tr - tg
                                    record_doc['DeliveryDelay'] = '{}'.format(d)
                                except Exception as err:
                                    print(err)
                            if 'timestamp' in record_doc:
                                record_doc['timestamp'] = datetime.datetime.fromisoformat(record_doc['timestamp']).strftime(timestamp_format)
                            dates = ['lastStatusUpdateDate','lastModifiedDate','createdDate']
                            for date in dates:
                                if date in record_doc:
                                    record_doc[date] = datetime.datetime.fromtimestamp(record_doc[date]/1000).strftime(timestamp_format)
                            logger.info('#####')
                            logger.info(record_doc)
                            logger.info('#####')
    else:
        # in case of failure, simply output the log to CloudWatch Logs
        print("Received event: " + json.dumps(jsonBody, indent=2))
        return False
    return True