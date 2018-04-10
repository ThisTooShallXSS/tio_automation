# Requirements: Python 2.7+, Tenable.io API access/secret keys
#
# Author: Dan Hewitt (with serious help from Andrew Scott!)
#
#     Check if you have 'pip' installed. If not:
#         curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"; python get-pip.py
#     Then run:
#         pip install tenable_io
#
# This script just takes the scan settings as command line args. You will need to hardcode your API keys and scanner name below.
# The way the script works is by kicking off a scan and waiting for the results to download them in '.nessus' format.
# If you launch with '&', it will put it into the background so that you can continue to use the CLI while the scan runs.
#
# python ezscan.py 'Example Scan - Basic' 'basic' '172.26.68.0/24' &
# python ezscan.py 'Example Scan - Shellshock' 'shellshock' '172.26.68.12' &
# python ezscan.py 'Example Scan - Discovery' 'discovery' '172.26.0.0/16' &
#
# Templates: (As of 1/17/17) - Note: Some of these require credentials.
#
# asv, wannacry, intelamt, discovery, basic, patch_audit, webapp, malware, mobile, 
# mdm, compliance, pci, offline, cloud_audit, scap, shellshock, ghost, drown, badlock,
# shadow_brokers, spectre_meltdown, advanced, agent_advanced, agent_basic, agent_compliance, agent_scap, agent_malware
#

import sys
from tenable_io.client import TenableIOClient
from tenable_io.api.scans import ScanExportRequest, ScanCreateRequest
from tenable_io.api.models import ScanSettings

scanName = sys.argv[1]
scanTemplate = sys.argv[2]
scanTarget = sys.argv[3]

# Replace with your own user's API access and secret keys
accessKey = ''
secretKey = ''

# Choose a scanner to use for the purposes of automated scanning
scannerName = 'tnsappliance-123456'

# Create a folder on Tenable.io where the API generated scans will go.
# Otherwise, we will simply put them into the default 'My Scans' folder.
folderName = 'My Scans'

# templates_list = [t.name for t in client.editor_api.list('scan').templates]
# print(templates_list)

# Establish the login session using our client API helper.
client = TenableIOClient(access_key=accessKey, secret_key=secretKey)

# Fetch a list of all scanners on the account and group them into a dictionary {scannerName: scannerId}
scanners = {scanner.name: scanner.id for scanner in client.scanners_api.list().scanners}

# Fetch a list of all folders on the account and group them into a dictionary {folderName: folderId}
folders = {folder.name: folder.id for folder in client.folders_api.list().folders}

# Fetch the template uuid to be used in our call to launch the scan.
template = client.scan_helper.template(name=scanTemplate)

# Create the scan and use the corresponding scanner id for the scanner name supplied
scan_id = client.scans_api.create(
    ScanCreateRequest(
        template.uuid,
        ScanSettings(
            scanName,
            scanTarget,
            folder_id=folders[folderName],
            scanner_id=scanners[scannerName]
        )
    )
)

# Get the scanRef object using the previously returned scan id
scan = client.scan_helper.id(scan_id)

# launch & download the scan result
scan.launch().download('{}.nessus'.format(scanName), scan.histories()[0].history_id, format=ScanExportRequest.FORMAT_NESSUS)
