#!/usr/bin/env python
#
# This script enables you to go through and programmatically replace AWS Connector
# credentials stored in Tenable.io.
#
# Script limitations:
# - Does not handle multiple trails per connector.
# - Doesn't have much error handling, only minimal logging.
# - No immediate way to know if new creds are successful or not.
#
# Author: Dan H
# Requirements: Python 3.7+
#
# Usage: 
# - python tio_api_change_aws_conn.py  (For interactive prompts)
# - python tio_api_change_aws_conn.py 'AWS Connector 123' ACCESSCODE123 SECRETCODE123 
#

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

class connector(object): # Object for storing existing connector details.
    def __init__(self, name, status, conn_id, conn_arn, trail_name):
        self.name = name
        self.status = status
        self.conn_id = conn_id
        self.conn_arn = conn_arn
        self.trail_name = trail_name

class new_creds(object): # Object for temp storing new AWS creds.
    def __init__(self, name, access, secret):
        self.name = name
        self.access = access
        self.secret = secret

def save_keys():
    #assumption is that the user keys didn't work or don't exsist
    print("Please provide your Tenable.io User API keys.")
    access_key = input("Please provide your Access Key (use quotes): ")
    secret_key = input("Please provide your Secret Key (use quotes): ")

    dicts = {"Access Key": access_key, "Secret Key": secret_key}

    pickle_out = open("keys.pickle", "wb")
    pickle.dump(dicts, pickle_out)
    pickle_out.close()

    print("Now you have keys, re-run your command")
    sys.exit()

def grab_headers():
    import os

    access_key = ''
    secret_key = ''

    #check for API keys; if none, get them from the user by calling save_keys()
    if os.path.isfile('./keys.pickle') is False:
        save_keys()
    else:
        pickle_in = open("keys.pickle", "rb")
        keys = pickle.load(pickle_in)
        access_key = keys["Access Key"]
        secret_key = keys["Secret Key"]

    #set the header
    headers = {'Content-type':'application/json',
               'X-ApiKeys':'accessKey='+access_key+';secretKey='+secret_key}
    return headers

def get_data(url_mod):
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.request('GET', url + url_mod, headers=headers, verify=False)

    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the initial GET request. Exiting.')
        sys.exit()

    data = r.json()
    return data

def get_connectors():
    data = get_data('/settings/connectors')
    connectors = []

    for x in range(len(data["connectors"])):
        # Go through each configured connector and store it's settings.
        connectors.append(connector(
            data["connectors"][x]["name"],
            data["connectors"][x]["status"],
            data["connectors"][x]["id"],
            data["connectors"][x]["params"]["trails"][0]["arn"],
            data["connectors"][x]["params"]["trails"][0]["name"]))

    return connectors

def put_connector_changes(connector_uuid, json_payload):
    # This makes the PUT request to replace credentials on T.io
    url = "https://cloud.tenable.com/settings/connectors/"
    headers = grab_headers()
    r = requests.request('PUT', url + connector_uuid, headers=headers, data=json_payload, verify=False)

    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the final PUT request. Exiting.')
        sys.exit()

    return True

def report_connector_options(connectors):
    # For all available connectors, this shows the name/status/ID for each.
    print('\nConnectors Available:')
    for x in range(len(connectors)):
        print("{} - {}  (Status: {})  (ID: {})").format(x, connectors[x].name, connectors[x].status, connectors[x].conn_id)

def get_connector_id_by_name(connectors, name):
    # This returns the UID of the connector when given a valid connector name.
    # Was previously used by our script, but has since been replaced with a simpler validity check.
    for x in range(len(connectors)):
        if connectors[x].name == name:
            ret = connectors[x].conn_id
    return ret

def check_valid_connector_by_name(connectors, name):
    # This returns True/False based on the existence of the AWS connector name.
    ret = False

    for x in range(len(connectors)):
        if connectors[x].name == name:
            ret = True
    return ret

def get_connector_obj_ref(connectors):
    # This isn't used in my script, but might be useful further down the road.
    print('\nPlease type the name of the connector you would like to change credentials for:')
    choice = raw_input(' >>> ')
    ret = ""

    for x in range(len(connectors)):
        if connectors[x].name == choice:
            ret = x
    return ret

def prompt_for_creds(name):
    # In case we're not provided the creds at runtime, we prompt for them here.
    print("Changing authentication tokens for '{}'.").format(name)
    access_key = raw_input(' Please provide your ACCESS key: ')
    secret_key = raw_input(' Please provide your SECRET key: ')
    ret = [access_key, secret_key]
    return ret

def store_creds(name):
    if len(sys.argv) == 4: # If argv3 & 4 are given, we use those
        access_key = sys.argv[2]
        secret_key = sys.argv[3]
    else:      # otherwise we prompt for which creds to use instead.
        creds_list = prompt_for_creds(name)
        access_key = creds_list[0]
        secret_key = creds_list[1]

    # Returns an object "new_creds"
    return new_creds(name, access_key, secret_key)

def trigger_connector_import(uuid):
    # This makes the POST request to update the AWS connector status
    url = "https://cloud.tenable.com/settings/connectors/"
    action = "/import"
    headers = grab_headers()
    r = requests.request('POST', url + uuid + action, headers=headers, verify=False)
    # POST https://cloud.tenable.com/settings/connectors/6100a0f7-0101-4f13-8e60-90be93ca16c3/import

    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the import POST request. Exiting.')
        sys.exit()

    return True    

def change_stored_creds(connectors, creds):
    for x in range(len(connectors)):
        if connectors[x].name == creds.name:

            # At this point, we've identified the connector we're editing, and parsing all new details.
            connector_uuid = connectors[x].conn_id
            trail_arn = connectors[x].conn_arn
            trail_name = connectors[x].trail_name

            # Grab user-supplied details
            access_key = creds.access
            secret_key = creds.secret
            connector_name = creds.name

            # Build out the JSON payload which is submitted to make the changes.
            json_payload1 = '{{"connector":{{"type":"aws","data_type":"assets","name":"{}",'.format(connector_name)
            json_payload2 = '"params":{{"trails":[{{"arn":"{}","name":"{}","region":{{"name":"All","friendly_name":"All"}},"availability":"success"}}],'.format(trail_arn, trail_name)
            json_payload3 = '"access_key":"{}","secret_key":"{}"}}}}}}'.format(access_key, secret_key)

            # Separated the payload into 3 vars for easier readability.
            json_payload = json_payload1 + json_payload2 + json_payload3
            #print('Payload to be submitted:\n\n%s\n' % json_payload)

            if put_connector_changes(connector_uuid, json_payload):
                print('The AWS credentials in Tenable.io have been replaced for "{}".').format(creds.name)
                trigger_connector_import(connector_uuid)
                outcome = True
            else:
                print('An error occurred when changing the AWS credentials for "{}".').format(creds.name)
                outcome = False
            break

    return outcome

def get_name_choice(connectors):
    # If someone has provided argv1, we query for that connector name's validity.
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else: # Otherwise, we give them the available connectors and have them choose.
        report_connector_options(connectors)
        print('\nPlease indicate the name of the connector you would like to change credentials for:')
        choice = raw_input(' >>> ')
    
    return choice

def main():
    try:
        connectors = get_connectors()
    except:
        print('Could not get connectors from Tenable.io... Quitting')
        sys.exit()

    connector_name = get_name_choice(connectors)
    new_creds = []
        
    if check_valid_connector_by_name(connectors, connector_name):
        new_creds = store_creds(connector_name)
        #print(cred_obj.name)

        change_stored_creds(connectors, new_creds)



if __name__ == '__main__':
    main()
