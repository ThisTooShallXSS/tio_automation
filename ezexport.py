# Requirements: Python 2.7+, Tenable.io API access/secret keys
#
# Author: Dan Hewitt
#
#     Check if you have 'pip' installed. If not:
#         curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"; python get-pip.py
#     Then run:
#         pip install tenable_io
#
# This script attempts to download the reports of existing scans in a variety of formats.
# Using regex, your call to the script looks for any scans which match the search criteria/regex.
# The downloaded report files will be saved to the same directory as where the script is ran from.
# If a specific folder is not mentioned, we will search in the default 'My Scans' folder.
# If you need to specify an auto-download format, be sure to also provide the folder name.
#
# ---- EXAMPLES ---- 
#
# python ezexport.py {scan name} {folder name} {export format}
#
# python ezexport.py 'PCI'
# python ezexport.py 'Daily Scan'
# python ezexport.py 'Test Scan' 'API Initiated Scans'
# python ezexport.py 'Daily' 'My Scans' 'nessus'
# python ezexport.py 'PCI' 'My Scans' 'html'

import time, sys
from tenable_io.client import TenableIOClient
from tenable_io.api.scans import ScanExportRequest

# Replace with your own user's API access and secret keys
accessKey = ''
secretKey = ''

# This is the argv that correpsonds to the search query for scan name.
scanNameQuery = sys.argv[1]

# Specify the folder where the scan is saved.
# Otherwise, we will simply search the default 'My Scans' folder.
if len(sys.argv) == 3:
    folderName = sys.argv[2]
else:
    folderName = 'My Scans'

# If a format is specified, a specific folder is necessary.
if len(sys.argv) == 4:
    folderName = sys.argv[2]
    scanFormat = sys.argv[3]

# Establish the login session using our client API helper.
client = TenableIOClient(access_key=accessKey, secret_key=secretKey)

# Fetch a list of all folders on the account and group them into a dictionary {folderName: folderId}
folders = {folder.name: folder.id for folder in client.folders_api.list().folders}

if folders:
    try:
        folder_id = folders[folderName]
    except:
        sys.exit("Invalid folder name: %s\n" % folderName)

# This is the regex which is used to search for the scan names.
scanQueryRegex = r".*{0}.*".format(scanNameQuery)

# This uses the scans helper to find the ScanRef object associated with the scan name.
scan = client.scan_helper.scans(name_regex=scanQueryRegex, folder_id=folder_id)

# The number of scans matching our search criteria
scan_count = len(scan)

print('\nNumber of scans found : %s' % scan_count)
print '-------------------'

# Iterate through each of the scans that were found
for result in scan:

    # Use result.details() to get the array of scan information, such as name or targets.
    details = result.details(result.histories()[0].history_id).info
    print("Scan Found : %s" % details.name)
    print("Host Count : %s" % details.hostcount)
    print("Last Runtime : %s\n" % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(details.timestamp)))

    try: # Attempt to use the export format from argv.
        export_type = scanFormat
    except NameError:

        if scan_count > 1:
            print 'Please choose an export file format (default: next) : html, csv, nessus, pdf OR quit OR next'
        else:
            print 'Please choose an export file format (default: quit) : html, csv, nessus, pdf OR quit'
        
        export_type = raw_input(" >>  ")

    acceptable_types = ["html", "csv", "nessus", "pdf", "quit", "next", ""] # Allow for blank/empty to skip/exit.

    if export_type not in acceptable_types: # Check if raw input given matches valid option.
        sys.exit("Invalid response - Quitting.\n")

    if len(export_type) > 0: # If anything is typed/present...
        if export_type == 'quit': # Quit upon request.
            sys.exit("Quitting.")

        if export_type == 'next': # Skip this one if 'next' is explicitly defined.
            scan_count = scan_count - 1
            print '--------Next Scan---------\n'
            continue

        print 'Downloading file, please wait...'
        scan_count = scan_count - 1 # Count down from the total number of scans.
        result.download('{}.{}'.format(details.name, export_type), result.last_history().history_id, format=export_type)

    else:
        if scan_count > 1: # At this point we have zero raw input from above.
            export_type = 'next'
        if scan_count == 1: # If we only ever had one scan to show, exit at this point.
            sys.exit("We've reached the end of list - Quitting.\n")

    if export_type == 'next': # If no input provided, quit or continue.
        scan_count = scan_count - 1

        if scan_count == 0:
            sys.exit("We've reached the end of list - Quitting.\n")
        else:
            print 'No input provided. Skipping...'
            print '--------Next Scan---------\n'
            continue

    # By this point we haven't skipped to the next scan or exited, so report successful download.
    print("\n*** File downloaded successfully : {}.{} ***".format(details.name, export_type))
    print '-------------------'

#fin
