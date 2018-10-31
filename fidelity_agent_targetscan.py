#!/usr/bin/env python
#
# This script queries assets in Tenable.io to find all assets scanned only by
# the Nessus Agent. It then takes these IPs and creates a target group and
# basic network scan (uncredentialed) against the new target group, and runs
# the scan. By the time the script is finished running, there should be a
# pending scan for all internal IPs seen only by Agent scans thus far.
#
# Script Assumptions:
# - You have an internal Nessus scanner deployed, and know the scanner name.
# - You have already deployed some Nessus Agents, but have not scanned them via Nessus remotely.
# - The argument you pass to the script covers a valid internal network range.
# - You are authorized to perform scans in your environment.
#
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7+
#
# Usage: 
# - python fidelity_agent_targetscan.py '10.0.0.0/8'
# - python fidelity_agent_targetscan.py '192.168.1.0/24'
# - python fidelity_agent_targetscan.py (Will find all internal (RFC-1918) IPs without CIDR specified)
#

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

TIMEFRAME = 90 # Time (in days) that we'll include in the search. 0 for all.
SCANNER_NAME = 'tnsappliance-123456' # Provide the name of an already linked scanner or group.
FOLDER_NAME = 'My Scans' # Provide the name of an already created folder.

class agent_only_assets(object): # Object for temp storing new AWS creds.
    def __init__(self, ipv4, fqdn):
        self.ipv4 = ipv4
        self.fqdn = fqdn

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

def create_target_group(req_type, ip_addrs, name):
    # This makes the POST request to build the target group on Tenable.io
    json_payload = '{{"name":"{}","members":"{}","type":"system","acls":[{{"permissions":64,"type":"default"}}]}}'.format(name, ip_addrs)
    url = "https://cloud.tenable.com/target-groups"
    headers = grab_headers()
    r = requests.request(req_type, url, headers=headers, data=json_payload, verify=False)
    
    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the POST request to create target group. Exiting.')
        sys.exit()

    tgt_group_id = r.json()["id"]

    return tgt_group_id

def get_agent_only_ips():

    uri = '/workbenches/assets?date_range={}&filter.0.quality=set-hasonly&filter.0.filter=sources&filter.0.value=PVS&filter.search_type=and'.format(TIMEFRAME)
    data = get_data(uri)
    ip_addrs = []

    for x in range(len(data["assets"])):
        # Go through each configured connector and store it's settings.
        for y in range(len(data["assets"][x]["ipv4"])):

            ip_addr = data["assets"][x]["ipv4"][y]
            try:
                fqdn = data["assets"][x]["fqdn"][0]
            except:
                fqdn = ''

            #print("IP: {}, FQDN: {}".format(ip_addr, fqdn))
            if check_valid_target(ip_addr):
                ip_addrs.append(agent_only_assets(ip_addr,fqdn))

    return ip_addrs

def check_valid_target(ip):
    try:
        cidr = sys.argv[1]
    except:
        cidr = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    if is_internal(ip):
        if ',' in cidr:
            for single_cidr in [x.strip() for x in cidr.split(',')]:
                    if addressInNetwork(ip, single_cidr): # Check if IP is part of allowable scan range.
                        return True
        else:
            if addressInNetwork(ip, cidr): # Check if IP is part of allowable scan range.
                return True

    return False

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

def addressInNetwork(ip, net):
    import socket,struct

    ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
    netstr, bits = net.split('/')
    netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
    mask = (0xffffffff << (32 - int(bits))) & 0xffffffff

    return (ipaddr & mask) == (netaddr & mask)

def create_ip_list(agent_only_ips):
    # Now, agent_only_ips is an object, with a variable length, each having an IP+fqdn.
    # We will use this list to create the target group of IPs in Tenable.io
    target_ips = ''
    for x in range(len(agent_only_ips)):
        if x == 0:
            target_ips = agent_only_ips[x].ipv4
        else:
            target_ips = target_ips + ',' + agent_only_ips[x].ipv4

    return target_ips

def get_scanner_id():
    scanners = get_data('/scanners')["scanners"]
    scanner_id = 0

    for x in range(len(scanners)):
        if SCANNER_NAME == scanners[x]["name"]:
            scanner_id = scanners[x]["uuid"]
            break
    if scanner_id == 0: print("Scanner name not found: {}".format(SCANNER_NAME))
    return scanner_id

def get_folder_id():
    folders = get_data('/folders')["folders"]
    folder_id = 0

    for x in range(len(folders)):
        if FOLDER_NAME == folders[x]["name"]:
            folder_id = folders[x]["id"]
            break

    if folder_id == 0: print("Folder name not found: {}".format(FOLDER_NAME))
    return folder_id

def get_template_id(name):
    templates = get_data('/editor/scan/templates')["templates"]
    template_id = 0

    for x in range(len(templates)):
        if name == templates[x]["name"]:
            template_id = templates[x]["uuid"]
            break
    if template_id == 0: print("Scan Template UUID not found: {}".format(name))
    return template_id

def run_basic_uncred_scan(target_group_id, timestamp):

    scanner_id = get_scanner_id()
    folder_id = get_folder_id()
    template_id = get_template_id('basic')

    #print("Scanner ID: {}, Folder ID: {}, Tgt Group ID: {}".format(scanner_id, folder_id, target_group_id))
    # POST to /scans
    #print("Good UUID: 731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65")
    #print("Found UUID: {}".format(template_id))
    # Need scanner-id, name, launch_now:true, folder_id, asset_lists:0:target_group_id
    scan_name = "Agent Only Assets Remote Scan - {}".format(timestamp)

    json_payload = '{{"uuid":"{}","settings":{{"launch_now":true,"enabled":false,"file_targets":"","text_targets":"","asset_lists":["{}"],"scanner_id":"{}","use_dashboard":"","folder_id":{},"description":"","name":"{}"}}}}'.format(template_id, target_group_id, scanner_id, folder_id, scan_name)
    url = "https://cloud.tenable.com/scans"
    headers = grab_headers()
    r = requests.request('POST', url, headers=headers, data=json_payload, verify=False)
    
    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the POST request to create the new scan. Exiting.')
        sys.exit()

    return True

def tg_name_exists(tg_name):
    target_groups = get_data('/target-groups')["target_groups"]

    for x in range(len(target_groups)):
        if tg_name == target_groups[x]["name"]:
            return True

    return False

def update_existing_tg(tg_id, ip_list, tg_name):
    create_target_group('PUT', target_group_ips, target_group_name)

   # This makes the POST request to build the target group on Tenable.io
    json_payload = '{{"name":"{}","members":"{}","type":"system","acls":[{{"permissions":64,"type":"default"}}]}}'.format(name, ip_addrs)
    url = "https://cloud.tenable.com/target-groups/{}".format(tg_id)            
    headers = grab_headers()
    r = requests.request(req_type, url, headers=headers, data=json_payload, verify=False)
    
    if r.status_code != 200:
        print('Status:', r.status_code, 'Problem with the POST request to create target group. Exiting.')
        sys.exit()

    tgt_group_id = r.json()["id"]

    return tgt_group_id

def create_dynamic_tg(agent_only_ips, timestamp):
    # Ensure that there is at least one IP returned in the query.
    target_group_name = 'Scanned Only by Agents (as of {})'.format(timestamp)
    target_group_ips = create_ip_list(agent_only_ips)
    target_group_id = tg_name_exists(target_group_name)

    if target_group_id > 0:
        target_group_id = update_existing_tg(target_group_id, target_group_ips, target_group_name)
    else:
        target_group_id = create_target_group('POST', target_group_ips, target_group_name)

    # Now that we have a list of the IPs only seen by the agent, we can create the target group.
    if target_group_id > 0:
        print('Target group created! (Name: {}, # of IPs: {})'.format(target_group_name, len(agent_only_ips)))
        print('\nDevices Included:')
        for x in range(len(agent_only_ips)):
            print(" - {} ({})".format(agent_only_ips[x].ipv4, agent_only_ips[x].fqdn))


def main():
    import datetime, time
    # First we grab all systems seen only by the Agents.
    try:
        agent_only_ips = get_agent_only_ips()
    except:
        print('Could not get asset details from Tenable.io... Quitting')
        sys.exit()

    if len(agent_only_ips) == 0:
        print("No assets found matching this network range.")
        sys.exit()
    else:
        ts = time.time()
        #timestamp = datetime.datetime.fromtimestamp(ts).strftime('%b-%d') # Month-Day
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M') # Year-Month-Day Hr:Min

        if create_dynamic_tg(agent_only_ips, timestamp):
            if run_basic_uncred_scan(target_group_id, timestamp):
                print("\nA basic uncredentialed Nessus scan has been initiated against the new target group.")

if __name__ == '__main__':
    main()
