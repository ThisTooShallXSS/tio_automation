#!/usr/bin/env python
#
# Summary:
# Given a CIDR address, this script will create a target group called
# "To Be Deleted - 10.85.0.0/16" for example, and then use that to
# filter assets belonging to that network, so they can then be deleted.
# The script will automatically delete any matching assets. Deletion
# may take up to a minute to be reflected in Tenable.io
#
# Note: Deleted assets are only removed from dashboards. The license is
#       unaffected by assets deleted through the UI or this script.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7, requests
#
# Usage: 
# - python delete_assets_large.py '10.18.0.0/16'    # Class-B (65k IPs)
# - python delete_assets_large.py '192.168.1.0/24'  # Class-C (254 IPs)
# - python delete_assets_large.py '192.168.1.13/32' # Single-IP deletion

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

DATE_RANGE_TO_DELETE = 30

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
        print('Status:', r.status_code, 'Problem with the initial GET assets request. Quitting...')
        sys.exit()

    data = r.json()
    return data

def delete_asset(uuid):
    url = "https://cloud.tenable.com"
    url_mod = "/workbenches/assets/{}".format(uuid)
    headers = grab_headers()

    r = requests.request('DELETE', url + url_mod, headers=headers, verify=False)
    
    if r.status_code != 202:
        print('Status:', r.status_code, 'Problem with the DELETE asset request. Exiting.')
        sys.exit()    

    return

def tg_name_exists(tg_name):
    target_groups = get_data('/target-groups')["target_groups"]

    for x in range(len(target_groups)):
        if tg_name == target_groups[x]["name"]:
            return target_groups[x]["id"]

    return 0

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
        print('Target group updated. Name: {}'.format(target_group_name))
        print("Members: {}\n".format(ip_list))

    return target_group_id

def purge_assets(assets):
    for x in range(len(assets)):
        try:
            delete_asset(assets[x])
        except:
            print("Could not delete asset uuid: {}").format(assets[x])

    return True

def addressInNetwork(ip, net):
    import socket,struct

    ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
    netstr, bits = net.split('/')
    netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
    mask = (0xffffffff << (32 - int(bits))) & 0xffffffff

    return (ipaddr & mask) == (netaddr & mask)

def find_matching_hosts(cidr_str):

    # Create target group with cidr_str
    tg_name = "To Be Deleted - {}".format(cidr_str)
    tg_id = create_tg(tg_name, cidr_str)

    if tg_id == 0:
        print("Target group could not be created for {}").format(cidr_str)
        sys.exit()

    tg_filtered_url = '/workbenches/assets?date_range={}&'\
                      'filter.0.quality=eq&filter.0.filter=target_group&'\
                      'filter.0.value={}&filter.search_type=and'.format(DATE_RANGE_TO_DELETE, tg_id)

    all_assets = get_data(tg_filtered_url)["assets"]

    if len(all_assets) < 1:
        print("No assets remaining from target group. Quitting...")
        sys.exit()

    matching_uuids = []
    cidr_quickmatch = cidr_str[0:3]

    for x in range(len(all_assets)):
        ipv4_data = all_assets[x]["ipv4"]

        for y in range(len(ipv4_data)):
            ip_quickmatch = ipv4_data[y][0:3]

            # take first 3 chars of asset IP, and ensure it matches first 3 of cidr.
            if ip_quickmatch == cidr_quickmatch:
                #print("Matching Asset. IP: {} ").format(ipv4_data[y])
                # if so, check against addressInNetwork() to see if it's to be added to the list.
                if addressInNetwork(ipv4_data[y], cidr_str):
                    matching_uuids.append(all_assets[x]["id"])

    return matching_uuids

def main():
    to_be_deleted = []

    try:
        cidr_arg = sys.argv[1]
    except:
        print("Please specify the CIDR where assets will be deleted. ex '192.168.2.0/24' (Use Quotes)")
        cidr_arg = input("> ")

    try:
        to_be_deleted = find_matching_hosts(cidr_arg)
    except:
        print("Could not fetch hosts to be deleted.")

    if len(to_be_deleted) > 0:
        print("Number of systems being deleted: {}").format(len(to_be_deleted))
        if purge_assets(to_be_deleted):
            print("Successful deletion.")
    else:
        print("No assets found matching this CIDR. Quitting...")

if __name__ == '__main__':
    main()
