#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2023, Wazuh Inc.
# All rights reserved.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath, Path

OS_SUCCESS = 0
OS_INVALID = -1

LOG_FILE = "/var/ossec/logs/active-responses.log"
MAL_IP_LIST  = "/var/ossec/etc/lists/mal-ip-list"
MAL_URL_LIST = "/var/ossec/etc/lists/mal-url-list"
MAL_MD5_LIST = "/var/ossec/etc/lists/mal-md5-list"

# Write a log file for debugging.
def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")) + " " + ar_name_posix + ": " + msg +"\n")

# Get alert data from STDIN
def read_alert_data():
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    try:
        alert_data = json.loads(input_str)
    except ValueError:
        write_debug_file(sys.argv[0], "Decoding JSON has failed, invalid input format")
        sys.exit(OS_INVALID)

    return alert_data

# Check for duplicated IoCs in the IoC files.
def is_not_duplicate_ioc(ioc_file, ioc):
    ioc += ":\n"
    for line in ioc_file:
        if line == ioc:
            return False

    return True

# Get the value of the alert object key if it exists.
def get_ioc_if_exist(alert_obj, keys):
    if not keys or alert_obj is None:
        return alert_obj

    return get_ioc_if_exist(alert_obj.get(keys[0]), keys[1:])

# Write unique IoCs to their respective files.
def write_ioc_file(ioc_list, ioc):
    if not Path(ioc_list).is_file():
        open(ioc_list, 'w').close()

    with open(ioc_list, "r+") as f:
        if is_not_duplicate_ioc(f, ioc):
            f.write(f"{ioc}:\n")
            write_debug_file(sys.argv[0], "ioc-data:" + "True|" + ioc + "|" + ioc_list)
        else:
            write_debug_file(sys.argv[0], "ioc-data:" + "False|" + ioc + "|" + ioc_list)

# Extract IoCs from security alerts.
def extract_iocs():
    alert_obj = read_alert_data()

    # Uniquely add the url to mal-url-list.
    url = get_ioc_if_exist(alert_obj, ["parameters", "alert", "data", "url"])
    if url is not None:
        write_ioc_file(MAL_URL_LIST, url)

    # Uniquely add the srcip to mal-ip-list.
    srcip = get_ioc_if_exist(alert_obj, ["parameters", "alert", "data", "srcip"])
    if srcip is not None:
        write_ioc_file(MAL_IP_LIST , srcip)

    # Uniquely add the file hash to mal-md5-list.
    md5_after = get_ioc_if_exist(alert_obj, ["parameters", "alert", "syscheck", "md5_after"])
    if md5_after is not None: # For FIM alert format.
        write_ioc_file(MAL_MD5_LIST, md5_after)

    md5 = get_ioc_if_exist(alert_obj, ["parameters", "alert", "data", "virustotal", "source", "md5"])    
    if md5 is not None: # For VT alert format.
        write_ioc_file(MAL_MD5_LIST, md5)

    id = get_ioc_if_exist(alert_obj, ["parameters", "alert", "data", "id"])
    if id is not None and len(id) == 32: # For ClamAV alert format. The id field represents the md5 hash.
        write_ioc_file(MAL_MD5_LIST, id)

def main(argv):

    write_debug_file(argv[0], "Started")

    extract_iocs()

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
