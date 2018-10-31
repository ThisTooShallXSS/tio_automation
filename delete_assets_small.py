#!/usr/bin/env python
#
# Summary:
# Given a CIDR address, and generally less than 5,000 total assets in
# Tenable.io, this script will go through and find all scanned assets
# that fall into that network range, and delete them. Deletion status 
# may take up to a minute to reflect in Tenable.io.
#
# Note: Deleted assets are only removed from dashboards. The license is
#       unaffected by assets deleted through the UI or this script.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7, requests
#
# Usage: 
# - python delete_assets_small.py '10.18.0.0/16'    # Class-B (65k IPs)
# - python delete_assets_small.py '192.168.1.0/24'  # Class-C (254 IPs)
# - python delete_assets_small.py '192.168.1.13/32' # Single-IP deletion

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
        print('Status:', r.status_code, 'Problem with the DELETE asset request. Quitting...')
        sys.exit()    

    return

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
	url = '/workbenches/assets?date_range={}'.format(DATE_RANGE_TO_DELETE)
    all_assets = get_data(url)["assets"]

    matching_uuids = []
    cidr_quickmatch = cidr_str[0:3]

    for x in range(len(all_assets)):
        ipv4_data = all_assets[x]["ipv4"]

        for y in range(len(ipv4_data)):
            ip_quickmatch = ipv4_data[y][0:3]

            # take first 3 chars of asset IP, and ensure it matches first 3 of cidr.
            if ip_quickmatch == cidr_quickmatch:
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
        print("Could not get hosts to be deleted. Quitting...")
        sys.exit()

    if len(to_be_deleted) > 0:
        print("Number of systems being deleted: {}").format(len(to_be_deleted))
        if purge_assets(to_be_deleted):
            print("Successful deletion.")
    else:
        print("No assets found matching this CIDR. Quitting...")

if __name__ == '__main__':
    main()
