#!/usr/bin/env python
#
# Notes:
# This script will go through and find all systems with vulns matching a certain
# threshold of severity, and for each severity, create a target group containing
# the IPs of hosts which have vulns in that severity.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7, requests
#
# Usage: 
# - python tg_severity_generator.py

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

SEVERITY_LIST = ['Low', 'Medium', 'High', 'Critical'] # Omitting INFO to reduce noise.
DATE_RANGE = '30' # Could be 7, 14, 30, 90, 0 (all)

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
        print('Status:', r.status_code, 'Problem with the initial GET assets request. Exiting.')
        sys.exit()

    data = r.json()
    return data

def tg_name_exists(tg_name):
    target_groups = get_data('/target-groups')["target_groups"]

    for x in range(len(target_groups)):
        if tg_name == target_groups[x]["name"]:
            return target_groups[x]["id"]

    return 0

def create_comma_sep_list(ip_list):
    ips = ''
    for x in range(len(ip_list)):
        ip_to_add = str(ip_list[x])

        if ip_to_add == '0.0.0.0':
            if len(ip_list) == 1:
                break
            else:
                continue

        if x == 0:
            ips = ip_to_add
        else:
            ips = ips + ',' + ip_to_add

    return ips

def update_existing_tg(tg_id, ip_list, tg_name):
    tgt_group_id = create_target_group('PUT', ip_list, tg_name, tg_id)

    return tgt_group_id

def create_target_group(req_type, ip_addrs, name, tg_id):
    # This makes the POST request to build the target group on Tenable.io
    json_payload = '{{"name":"{}","members":"{}","type":"system","acls":[{{"permissions":64,"type":"default"}}]}}'.format(name, ip_addrs)
    url = "https://cloud.tenable.com/target-groups"

    if tg_id > 0:
        url = url + '/{}'.format(tg_id)

    headers = grab_headers()
    r = requests.request(req_type, url, headers=headers, data=json_payload, verify=False)
    
    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the POST request to create target group. Exiting.')
        sys.exit()

    tgt_group_id = r.json()["id"]

    return tgt_group_id

def create_tg(name, ip_list):
    # Ensure that there is at least one IP returned in the query.
    target_group_name = name
    target_group_id = tg_name_exists(target_group_name)

    if target_group_id > 0:
        target_group_id = update_existing_tg(target_group_id, ip_list, target_group_name)
    else:
        target_group_id = create_target_group('POST', ip_list, target_group_name, 0)

    # Now that we have a list of the IPs only seen by the tag, we can create the target group.
    if target_group_id > 0:
        print('Target group updated. Name: {} - (IPs: {})'.format(target_group_name, len(ip_list.split(','))))
        print("{}\n".format(ip_list))

def get_severity_IPs(severity):
    #from pprint import pprint
    tg_data = []
    comma_ip_list = ''

    uri = '/workbenches/assets/vulnerabilities?date_range={}&'\
          'filter.0.quality=eq&filter.0.filter=severity&'\
          'filter.0.value={}&filter.search_type=and'.format(DATE_RANGE, severity)

    severity_hosts = get_data(uri)

    #pprint(severity_hosts)

    total_hosts_included = len(severity_hosts['assets'])
    ip_list = []
    
    if total_hosts_included == 0:
        print('No results returned for severity {}. Skipping').format(severity)   
    else:
        if total_hosts_included > 5000:
            print('This script meant to handle less-than 5000 hosts per query')
        else:
            assets = severity_hosts['assets']

            for y in range(len(assets)):
                if assets[y]['ipv4']:
                    ip_list.append(assets[y]['ipv4'][0])

            if len(ip_list) == 0:
                print('No host IPs are present for this severity ({}).').format(severity) 
            else:
                comma_ip_list = create_comma_sep_list(ip_list)

    return comma_ip_list

def main():

    for x in range(len(SEVERITY_LIST)):
        severity_ips = get_severity_IPs(SEVERITY_LIST[x])

        tg_name = 'zHosts with {} Vuln Results'.format(SEVERITY_LIST[x])

        if len(severity_ips) > 0:
                create_tg(tg_name, severity_ips)

if __name__ == '__main__':
    main()
