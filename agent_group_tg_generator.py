#!/usr/bin/env python
#
# Notes:
# This script will go through and find the IPs of all agents in each agent group,
# and create a corresponding target group for each group to use for filtering, reporting,
# or remote scanning purposes with Nessus.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7+
#
# Usage: 
# - python agent_group_tg_generator.py

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

class agent_group(object): # Object for temp storing new AWS creds.
    def __init__(self, group_id, name):
        self.group_id = group_id
        self.name = name

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
        if is_internal(ip_list[x]): # Makes sure we're only adding RFC-1918 internal IPs.
            if len(ips) < 1:
                ips = ip_list[x]
            else:
                ips = ips + ',' + ip_list[x]

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
    target_group_name = 'Agent Group - {}'.format(name)
    target_group_id = tg_name_exists(target_group_name)

    if target_group_id > 0:
        target_group_id = update_existing_tg(target_group_id, ip_list, target_group_name)
    else:
        target_group_id = create_target_group('POST', ip_list, target_group_name, 0)

    # Now that we have a list of the IPs only seen by the tag, we can create the target group.
    if target_group_id > 0:
        print('Target group created! (Name: {})'.format(target_group_name))
        print('Devices Included: {}').format(len(ip_list.split(',')))
        print("{}\n".format(ip_list))

def is_internal(ip):

    from struct import unpack
    from socket import AF_INET, inet_pton

    # First we make sure that it's a private/internal IP address.
    f = unpack('!I',inet_pton(AF_INET,ip))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0
    )
    for net in private: # If this IP address is an internal IP, proceed.
        if (f & net[1]) == net[0]:
            return True

    return False

def get_agent_scanner_id(manager_name):
    scanners = get_data('/scanners')["scanners"]

    for x in range(len(scanners)):
        if manager_name in scanners[x]["name"]:
            agent_scanner_id = scanners[x]["id"]

    return agent_scanner_id

def get_agent_groups(scanner_id):
    from pprint import pprint
    agent_groups = []
    uri = '/scanners/{}/agent-groups'.format(scanner_id)
    agent_groups_raw = get_data(uri)["groups"]

    for x in range(len(agent_groups_raw)):
        group_data = agent_groups_raw[x]
        agent_groups.append(agent_group(group_data['id'], group_data['name']))

    return agent_groups

def get_agent_ips(scanner_id, group_id):  
    agent_ips = []
    filter_options = '?offset=0&limit=5000&sort=name:asc'
    group_option = '&f=groups:eq:{}&ft=and'.format(group_id)
    uri = '/scanners/{}/agents{}{}'.format(scanner_id, filter_options, group_option)

    agents = get_data(uri)["agents"]

    for x in range(len(agents)):
        agent_ips.append(agents[x]['ip'])

    return agent_ips

def main():
    scanner_id = get_agent_scanner_id('US Cloud Scanner')
    agent_groups = get_agent_groups(scanner_id)

    for x in range(len(agent_groups)):
        agent_ip_list = get_agent_ips(scanner_id, agent_groups[x].group_id)

        if len(agent_ip_list) > 0:
            tg_ip_list = create_comma_sep_list(agent_ip_list)
            create_tg(agent_groups[x].name, tg_ip_list)

if __name__ == '__main__':
    main()
