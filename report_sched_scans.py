#!/usr/bin/env python
#
# This script enumerates all tenable.io scheduled scans.
#
# Author: ThisTooShallXSS
# (https://github.com/thistooshallxss)
#
# Requirements: requests, pickle
#
# Usage: 
# - python report_sched_scans.py 


import json, requests
import sys
import pickle

requests.packages.urllib3.disable_warnings()

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

class scan(object): # Object for storing existing connector details.
    def __init__(self, name, _type, status, rrules, starttime, timezone):
        self.name = name
        self._type = _type
        self.status = status
        self.rrules = rrules
        self.starttime = starttime
        self.timezone = timezone

def get_sched_scans(): # Uses class above to store scheduled scan details.
    data = get_data('/scans')
    scans = []

    # Example JSON:
    '''"timezone": "US/Eastern",
        "rrules": "FREQ=DAILY;INTERVAL=1",
        "starttime": "20180227T040000",
        "enabled": true,
        "control": true,
        "name": "Daily Agent Scan",
        "id": 4111'''

    for x in range(len(data["scans"])): # Iterate through all tio scans
        if data["scans"][x]["enabled"]: # Make sure that 'enabled' is true
            if data["scans"][x]["rrules"]: # Make sure that 'rrules' is not null.
                
                sched_scan = data["scans"][x] # Give us an easy var to reference for the scan in question.

                # Go through each configured connector and store it's settings.
                scans.append(scan(
                    sched_scan["name"], # Store the name of the scan.
                    sched_scan["type"], # Type of scan: webapp, remote, local, agent
                    sched_scan["status"], # Status of the scan, currently unused by this script.
                    sched_scan["rrules"], # Schedule rules of the scan: interval/frequency/sched
                    sched_scan["starttime"], # The next scheduled start time for the scan
                    sched_scan["timezone"] # The timezone indicated when the scan was scheduled.
                    ))

    return scans

def parse_rrules_schedule(rrules):
    sched = 'Every' # First word in the str
    retyped = ''
    parts = rrules.split(';')  #"rrules": "FREQ=DAILY;INTERVAL=1",
    frequency = parts[0].split('=')[1] # DAILY
    interval = int(parts[1].split('=')[1]) # 1

    if interval is 1:
        if frequency[0] == 'D':
            retyped = 'Day' # Every Day
        elif frequency[0] == 'W':
            retyped = 'Week' # Every Week
        elif frequency[0] == 'M':
            retyped = 'Month' # Every Month
    else:
        if frequency[0] == 'D':
            retyped = 'Days' # Every X Days
        elif frequency[0] == 'W':
            retyped = 'Weeks' # Every X Weeks
        elif frequency[0] == 'M':
            retyped = 'Months' # Every X Months
        sched = ('{} {}'.format(sched, interval))# So at this point we have 'Every 2 {freq}'

    try:
        if parts[2][0] == 'B': # "FREQ=DAILY;INTERVAL=1;BYDAY=MO,WE,FR"
            daysall = ''
            days = parts[2].split('=')[1].split(',')

            for x in range(len(days)):
                if x == 0:
                    daysall = days[x]
                else:
                    daysall = ('{}, {}'.format(daysall, days[x]))

            sched = ('{} {} on {}'.format(sched, retyped, daysall)) # Concatenates the three strings like: Every Week on MO,WE,SA
    except:
        sched = ('{} {}'.format(sched, retyped)) # Concatenates two like: Every Day

    return sched

def get_next_runtime(timestamp): 
    import dateutil.parser

    time = dateutil.parser.parse(timestamp) # "starttime": "20171019T220000"
    readable_time = time.strftime('%m/%d/%Y %I:%M %p')  #==> '09/26/2008 05:00 AM'

    return readable_time

def report_sched_scans(scans):
    for x in range(len(scans)):

        next_starttime = get_next_runtime(scans[x].starttime) # Get date of next run
        schedule = parse_rrules_schedule(scans[x].rrules) # Find out how often the scan runs.

        print('------')
        print('Name: {} (Type: {})'.format(scans[x].name.encode("utf-8"), scans[x]._type))
        print('Schedule: {}'.format(schedule))
        print('Next Runtime: {} ({})\n'.format(next_starttime, scans[x].timezone))

    return True

def main():
    try:
        scans = get_sched_scans()
    except:
        print('Could not get scans from Tenable.io... Quitting')
        sys.exit()
    
    report_sched_scans(scans)

if __name__ == '__main__':
    main()
