#!/usr/bin/env python
#
# Notes:
# This script will go through and find all created tags. Then, it'll
# find all systems that have each tag, take their IPs, and put them into
# a target group.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7+
#
# Usage: 
# - python tag_tg_generator.py

import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

class tag_obj(object): # Tag array details
    def __init__(self, category, value, tag_type):
        self.category = category
        self.value = value
        self.tag_type = tag_type # static or dynamic.

class tagged_ips(object): # What we need for creating target groups
    def __init__(self, tag_name, ip_list):
        self.tag_name = tag_name # Tag "category" + "value" + type
        self.ip_list = ip_list # Must be comma delimited str of IPs

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

def get_tags():
    tags = []
    tag_data = get_data('/tags/values')
    total_tags = tag_data['pagination']['total']
    tag_array = tag_data['values']

    for x in range(total_tags):
        tags.append(tag_obj(tag_array[x]['category_name'],
                            tag_array[x]['value'],
                            tag_array[x]['type']))
    return tags

def get_tag_IPs(tags):
    tg_data = []
    DATE_RANGE = '90'

    for x in range(len(tags)):

        tag_category = tags[x].category
        tag_value = tags[x].value
        tag_type = tags[x].tag_type

        uri = '/workbenches/assets?date_range={}&'\
              'filter.0.quality=set-has&filter.0.filter=tag.{}&'\
              'filter.0.value={}&filter.search_type=and'.format(DATE_RANGE, tag_category, tag_value)

        tagged_hosts = get_data(uri)
        total_tagged_hosts = tagged_hosts['total']
        ip_list = []
        
        if total_tagged_hosts == 0:
            print('No hosts found for tag. Skipping {}:{}').format(tag_category, tag_value)   
        else:
            if total_tagged_hosts > 5000:
                break

            assets = tagged_hosts['assets']
            for y in range(len(assets)):
                if assets[y]['ipv4']:
                    ip_list.append(assets[y]['ipv4'][0])

            if len(ip_list) == 0:
                print('No host IPs are present for this tag. Skipping {}:{}').format(tag_category, tag_value) 
            else:
                comma_ip_list = create_comma_sep_list(ip_list)
                tag_name = 'zTag: {} - {} ({})'.format(tag_category, tag_value, tag_type)
                tg_data.append(tagged_ips(tag_name, comma_ip_list))

    return tg_data

def main():
    tags = get_tags()
    if len(tags) == 0:
        print('No tags found. Please create a tag and re-run this script.')
        sys.exit()

    tagged_ips = get_tag_IPs(tags)

    for x in range(len(tagged_ips)):
        if len(tagged_ips[x].ip_list) > 0:
            create_tg(tagged_ips[x].tag_name, tagged_ips[x].ip_list)

if __name__ == '__main__':
    main()
