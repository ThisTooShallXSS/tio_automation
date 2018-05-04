#!/usr/bin/env python 
#
# This script makes use of Nessus Network Monitor (NNM)'s ability to detect new hosts in real-time.
# When a new host is observed for the first time, a log event 'new-host-alert' is produced.
# These events can be written to syslog, or a file on disk - For this scripts purpose, the latter.
# When we see a new host alert from NNM, we can use that to initiate a Nessus scan against that host.
# Alternatively, you could have this script utilize smtp lib to send out an email notification.
#
# Requirements: NNM 5.4+, Python 2.7+, pygtail, Tenable.io API access/secret keys
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
#
# In order to use the following script, you will need to do the following:
#     /opt/nnm/bin/nnm --config 'Realtime Events File Size' '1G'
#     /opt/nnm/bin/nnm --config 'Log Realtime Events To Realtime Log File' 1
#     /opt/nnm/bin/nnm --config 'Maximum Realtime Log Files' 1
#
# To install additional Python libraries, you could use Pip. To auto-install:
#     curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"; python get-pip.py
#
# And now install the two necessary Python libraries:
#     pip install tenable_io
#     pip install pygtail
#
# To set this up:
#   - Change the 'SCANNER_NAME' to the name of one of your internal Nessus scanners.
#   - Create the folder in Tenable.io specified below as 'FOLDER_NAME'
#   - Update/change the 'ALLOWED_SCAN_RANGE' to include only IPs you wish to scan.
#   - Change the 'TEMPLATE_TYPE' variable to reflect the scan template used for the scan.
#
# Template Types: (As of 1/17/17)
# asv, wannacry, intelamt, discovery, basic, patch_audit, webapp, malware, mobile, 
# mdm, compliance, pci, offline, cloud_audit, scap, shellshock, ghost, drown, badlock,
# shadow_brokers, spectre_meltdown, advanced, agent_advanced, agent_basic, agent_compliance, agent_scap, agent_malware
#
# To automate the operation of this script, run 'crontab -e' and add the following:
#
#    */10 * * * * /root/scripts/tio_nnm_launch_scan.py
#

from tenable_io.client import TenableIOClient
from tenable_io.api.scans import ScanCreateRequest
from tenable_io.api.models import ScanSettings
from tenable_io.api.models import Scan
import sys

REALTIME_LOG_PATH = "/opt/nnm/var/nnm/logs/realtime-logs.txt"
ACCESSKEY = ''
SECRETKEY = ''

SCANNER_NAME = 'tnsappliance-123456'
FOLDER_NAME = "NNM Initiated Scans" # Will not auto-create folder. Must manually create in UI first.
TEMPLATE_TYPE = 'basic'

ALLOWED_SCAN_RANGE = '172.26.0.0/16' # Multiple scan ranges not yet supported.

class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

sys.stdout = Logger("New_Host_Tracking_Log.txt")   # This creates a log file for all stdout to write to.
tio_client = TenableIOClient(access_key=ACCESSKEY, secret_key=SECRETKEY)

def pygtail_check_logs():

    from pygtail import Pygtail
    key_phrases = ["new-host-alert"]            # This is where we can add additional realtime-events to trigger based on.

    for line in Pygtail(REALTIME_LOG_PATH):
        if 'nnm:' in line:                      # This line is in case we're looking at /var/log/messages instead.
                for phrase in key_phrases:      # Look for any real-time alerts which we want to act upon.
                    if phrase in line:  
                        process_log(line)

def process_log(line):

    import datetime, time
    import ipaddress

    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    # Oct 25 15:31:40 nnm: 192.168.11.100:0|0.0.0.0:0|6|13|new-host-alert|NNM identifies new hosts that have been seen within the monitored network range.|00:22:bd:f8:19:ff|INFO

    f = line.split()[4]                  # 192.168.11.100:0|0.0.0.0:0|6|13|new-host-alert
    ip_port = f.split('|')[0]            # 192.168.11.100:0
    new_host_ip = ip_port.split(':')[0]  # 192.168.11.100

    valid_target = check_valid_target(new_host_ip)

    # Only run automatic scans against internal RFC-1918 addresses.
    if valid_target:
        print("%s|%s|A basic network scan has been launched against %s" % (timestamp, new_host_ip, new_host_ip))

        init_scan(new_host_ip, timestamp)

def check_valid_target(ip):

    from struct import unpack
    from socket import AF_INET, inet_pton
    import ipaddress

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
            if addressInNetwork(ip, ALLOWED_SCAN_RANGE): # Check if IP is part of allowable scan range.
                return True
    return False

def addressInNetwork(ip, net):
   import socket,struct
   
   ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
   netstr, bits = net.split('/')
   netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
   mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
   
   return (ipaddr & mask) == (netaddr & mask)

def init_scan(new_host_ip, timestamp):
    # Fetch a list of all scanners on the account and group them into a dictionary {scannerName: scannerId}
    scanners = {scanner.name: scanner.id for scanner in tio_client.scanners_api.list().scanners}

    # Fetch a list of all folders on the account and group them into a dictionary {folderName: folderId}
    folders = {folder.name: folder.id for folder in tio_client.folders_api.list().folders}

    # This controls the name formatting for the automatically generated scan.
    scan_name = 'NNM Initiated Scan - New Host %s @ %s' % (new_host_ip, timestamp)

    # This controls which template is used, see the 'TEMPLATE_TYPE' variable at the top.
    basic_template = tio_client.scan_helper.template(name=TEMPLATE_TYPE)

    # Create the scan and use the corresponding scanner id for the scanner name supplied
    scan_id = tio_client.scans_api.create(
        ScanCreateRequest(
            basic_template.uuid,
            ScanSettings(
                scan_name,
                new_host_ip,
                folder_id=folders[FOLDER_NAME],
                scanner_id=scanners[SCANNER_NAME]
            )
        )
    )

    # Get the scanRef object using the previously returned scan id
    scan_ref = tio_client.scan_helper.id(scan_id)

    # launch the scan but don't block until it finishes
    scan_ref.launch(wait=False)


def main():
    pygtail_check_logs()

if __name__ == "__main__":
    main()
