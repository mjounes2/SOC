#!/usr/bin/env python

# Copyright Andreas Misje 2023, 2022 Aurora Networks Managed Services 
# See https://github.com/misje/wazuh-opencti for documentation
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import re
import traceback

# Debug can be enabled by setting the internal configuration setting
# intergration.debug to 1 or higher:
debug_enabled = False
null_string = 'null'
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# Match SHA256:
regex_file_hash = re.compile('[A-Fa-f0-9]{64}')
# Match sysmon_eventX, sysmon_event_XX, systemon_eidX(X)_detections, and sysmon_process-anomalies:
sha256_sysmon_event_regex = re.compile('sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)|process-anomalies)')
# Match sysmon_event3 and sysmon_eid3_detections:
sysmon_event3_regex = re.compile('sysmon_(?:event|eid)3')
# Match sysmon_event_22 and sysmon_eid22_detections:
sysmon_event22_regex = re.compile('sysmon_(?:event_|eid)22')
# Location of source events file:
log_file = '{0}/logs/integrations.log'.format(pwd)
# UNIX socket to send detections events to:
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
# Find ";"-separated entries that are not prefixed with "type: X ". In order to
# avoid non-fixed-width look-behind, match against the unwanted prefix, but
# only group the match we care about, and filter out the empty strings later:
dns_results_regex = re.compile(r'type:\s*\d+\s*[^;]+|([^\s;]+)')

def main(args):
    debug('# Starting')
    alert_path = args[1]
    # Documentation says to do args[2].split(':')[1], but this is incorrect:
    token = args[2]
    url = args[3]

    debug('# API key: {}'.format(token))
    debug('# Alert file location: {}'.format(alert_path))

    with open(alert_path, errors='ignore') as alert_file:
        alert = json.load(alert_file)

    debug('# Processing alert:')
    debug(alert)

    info = query_opencti(alert, url, token)

    if info:
        send_event(info, alert['agent'])

def debug(msg, do_log = False):
    do_log |= debug_enabled
    if not do_log:
        return

    now = time.strftime('%a %b %d %H:%M:%S %Z %Y')
    msg = '{0}: {1}\n'.format(now, msg)
    f = open(log_file,'a')
    f.write(msg)
    f.close()

def log(msg):
    debug(msg, do_log=True)

# Recursively remove all empty nulls, strings, empty arrays and empty dicts
# from a dict:
def remove_empties(value):
    # Keep booleans, but remove '', [] and {}:
    def empty(value):
        return False if isinstance(value, bool) else not bool(value)
    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    elif isinstance(value, dict):
        return {key: val for key, val in ((key, remove_empties(val)) for key, val in value.items()) if not empty(val)}
    else:
        return value

# Given an object 'output' with ha list of objects (edges and noodes) at key
# 'listKey', create a new list at key 'newKey' with just values from the
# original list's objects at key 'valueKey'. Example: 
# {'objectLabel': {'edges': [{'node': {'value': 'cryptbot'}}, {'node': {'value': 'exe'}}]}}
# →
# {'labels:': ['cryptbot', 'exe']}
def simplify_objectlist(output, listKey, valueKey, newKey):
    edges = output[listKey]['edges']
    output[newKey] = [key[valueKey] for edge in edges for _, key in edge.items()]
    if newKey != listKey:
        # Delete objectLabels (array of objects) now that we have just the names:
        del output[listKey]

# Take a string, like
# "type:  5 youtube-ui.l.google.com;::ffff:142.250.74.174;::ffff:216.58.207.206;::ffff:172.217.21.174;::ffff:142.250.74.46;::ffff:142.250.74.110;::ffff:142.250.74.78;::ffff:216.58.207.238;::ffff:142.250.74.142;",
# discard records other than A/AAAA, ignore non-global addresses, and convert
# IPv4-mapped IPv6 to IPv4:
def format_dns_results(results):
    def unmap_ipv6(addr):
        if type(addr) is ipaddress.IPv4Address:
            return addr

        v4 = addr.ipv4_mapped
        return v4 if v4 else addr

    try:
        # Extract only A/AAAA records (and discard the empty strings):
        results = list(filter(len, dns_results_regex.findall(results)))
        # Convert IPv4-mapped IPv6 to IPv4:
        return list(map(lambda x: unmap_ipv6(ipaddress.ip_address(x)).exploded, results))
    except ValueError:
        return []

def send_event(msg, agent = None):
    if not agent or agent['id'] == '000':
        string = '1:opencti:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->opencti:{3}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any', json.dumps(msg))

    debug('# Event:')
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def send_error_event(msg, agent = None):
    send_event({'integration': 'opencti', 'opencti': {'error': msg}}, agent)

def query_opencti(alert, url, token):
    # The OpenCTI graphql query is filtering on a key and a list of values. By
    # default, this key is "value", unless set to "hashes_SHA256":
    filter_key='value'
    groups = alert['rule']['groups']

    # TODO: Look up registry keys/values? No such observables in OpenCTI yet from any sources

    # In case a key or index lookup fails, catch this and gracefully exit. Wrap
    # logic in a try–catch:
    try:
        # For any sysmon event that provides a sha256 hash (matches the group
        # name regex):
        if any(True for _ in filter(sha256_sysmon_event_regex.match, groups)):
            filter_key='hashes_SHA256'
            # It is not a 100 % guaranteed that there is a (valid) sha256 hash
            # present in the metadata. Quit if no hash is found:
            match = regex_file_hash.search(alert['data']['win']['eventdata']['hashes'])
            if match:
                filter_values = [match.group(0)]
            else:
                sys.exit()
        # Sysmon event 3 contains IP addresses, which will be queried:
        elif any(True for _ in filter(sysmon_event3_regex.match, groups)):
            filter_values = [alert['data']['win']['eventdata']['destinationIp']]
            if not ipaddress.ip_address(filter_values[0]).is_global:
                sys.exit()
        # Group 'ids' may contain IP addresses.
        # This may be tailored for suricata, but we'll match against the "ids"
        # group. These keys are probably used by other decoders as well:
        elif 'ids' in groups:
            # Look up either dest or source IP, whichever is public:
            filter_values = [next(filter(lambda x: ipaddress.ip_address(x).is_global, [alert['data']['dest_ip'], alert['data']['src_ip']]), None)]
            if not filter_values:
                sys.exit()
        # Look up domain names in DNS queries (sysmon event 22), along with the
        # results (if they're IPv4/IPv6 addresses (A/AAAA records)):
        elif any(True for _ in filter(sysmon_event22_regex.match, groups)):
            query = alert['data']['win']['eventdata']['queryName']
            results = format_dns_results(alert['data']['win']['eventdata']['queryResults'])
            filter_values = [query] + results
        # Look up sha256 hashes for files added to the system or files that have been modified:
        elif 'syscheck_file' in groups and any(x in groups for x in ['syscheck_entry_added', 'syscheck_entry_modified']):
            filter_key = 'hashes_SHA256'
            filter_values = [alert['syscheck']['sha256_after']]
        # Look up sha256 hashes in columns of any osqueries:
        # Currently, only osquery_file is defined in wazuh_manager.conf, but add 'osquery' for future use(?):
        elif any(x in groups for x in ['osquery', 'osquery_file']):
            filter_key = 'hashes_SHA256'
            filter_values = [alert['data']['osquery']['columns']['sha256']]
        # Nothing to do:
        else:
            sys.exit()

    # Don't treat a non-existent index or key as an error. If they don't exist,
    # there is certainly no alert to make. Just quit:
    except IndexError:
        sys.exit()
    except KeyError:
        sys.exit()

    query_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accept': '*/*'
    }
    # Look for hashes, addresses and domain names is as many places as
    # possible, and return as much information as possible. Note that more data
    # is queried than is currently used. This should be removed:
    api_json_body={'query': 'query StixCyberObservables($types: [String] $filters: [StixCyberObservablesFiltering] $search: String $first: Int $after: ID $orderBy: StixCyberObservablesOrdering $orderMode: OrderingMode) {stixCyberObservables(types: $types filters: $filters search: $search first: $first after: $after orderBy: $orderBy orderMode: $orderMode) {edges {node {id created_at updated_at createdBy {... on Identity {id standard_id identity_class name} ... on Organization {x_opencti_organization_type x_opencti_reliability} ... on Individual {x_opencti_firstname x_opencti_lastname}} objectLabel {edges {node {value}}} externalReferences {edges {node {source_name url}}} observable_value x_opencti_description x_opencti_score indicators {edges {node {id valid_until revoked confidence x_opencti_score x_opencti_detection indicator_types x_mitre_platforms objectLabel {edges {node {value}}} killChainPhases{edges {node {kill_chain_name}}}}}} ... on AutonomousSystem {number name rir} ... on Directory {path} ... on DomainName {value} ... on EmailAddr {value display_name} ... on EmailMessage {message_id subject body} ... on Artifact {mime_type payload_bin url encryption_algorithm decryption_key hashes {algorithm hash} importFiles {edges {node {name size}}}} ... on StixFile {extensions size name x_opencti_additional_names hashes {algorithm hash}} ... on X509Certificate {is_self_signed serial_number signature_algorithm issuer subject validity_not_before validity_not_after hashes {algorithm hash}} ... on IPv4Addr {value} ... on IPv6Addr {value} ... on MacAddr {value} ... on Mutex {name} ... on NetworkTraffic {extensions start end is_active src_port dst_port protocols src_byte_count dst_byte_count src_packets dst_packets} ... on Process {extensions is_hidden pid created_time cwd command_line environment_variables} ... on Software {name cpe swid languages vendor version} ... on Url {value} ... on UserAccount {extensions user_id credential account_login account_type display_name is_service_account is_privileged can_escalate_privs is_disabled account_created account_expires credential_last_changed account_first_login account_last_login} ... on WindowsRegistryKey {attribute_key modified_time number_of_subkeys} ... on WindowsRegistryValueType {name data data_type} ... on X509Certificate {basic_constraints name_constraints policy_constraints key_usage extended_key_usage subject_key_identifier authority_key_identifier subject_alternative_name issuer_alternative_name subject_directory_attributes crl_distribution_points inhibit_any_policy private_key_usage_period_not_before private_key_usage_period_not_after certificate_policies policy_mappings} ... on CryptographicKey {value} ... on CryptocurrencyWallet {value} ... on Hostname {value} ... on Text {value} ... on UserAgent {value} importFiles {edges {node {name size}}}}} pageInfo {startCursor endCursor hasNextPage hasPreviousPage globalCount}}}' , 'variables': {'types': null_string, 'filters': [{'key': f'{filter_key}', 'values': filter_values}]}}
    debug('# Query:')
    debug(api_json_body)

    alert_output = {}
    try:
        response = requests.post(url, headers=query_headers, json=api_json_body)
    # Create an alert if the OpenCTI service cannot be reached:
    except ConnectionError:
        log('Failed to connect to {}'.format(url))
        send_error_event('Failed to connect to the OpenCTI API', alert['agent'])
        sys.exit(1)

    try:
        response = response.json()
    except json.decoder.JSONDecodeError:
        # If the API returns data, but not valid JSON, it is typically an error
        # code.
        log('# Failed to parse response from API')
        send_error_event('Failed to parse response from OpenCTI API', alert['agent'])
        sys.exit(1)

    debug('# Response:')
    debug(response)

    # TODO: Do something if pageInfo says there is more data to fetch, either
    # fetch or create an error event (there should never be that many results?)
    for edge in response['data']['stixCyberObservables']['edges']:
        node = edge['node']

        # Create a list of the individual node objects in indicator edges:
        indicators = list(map(lambda x:x['node'], node['indicators']['edges']))
        # If the observable has no indicators, ignore it:
        if not indicators:
            debug(f'# Observable found ({node["id"]}), but it has no indicators')
            continue

        # Generate alert output from OpenCTI Response. Some of the values will
        # be modified below (in particular, Wazuh/Opensearch doesn't like
        # arrays of objects):
        alert_output['integration'] = 'opencti'
        alert_output['opencti'] = edge['node']

        # Generate a link to the observable:
        alert_output['opencti']['observable_link'] = url.removesuffix('graphql') + 'dashboard/observations/observables/{0}'.format(node['id'])

        # Get rid of the hashes in the reply. We will use the hashes from the
        # source event instead (TODO: remove hashes from grapqhl query):
        if 'hashes' in alert_output['opencti']:
            del alert_output['opencti']['hashes']

        # Extract URIs from external references:
        simplify_objectlist(alert_output['opencti'], listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')
        # Convert list of file objects to list of file names:
        simplify_objectlist(alert_output['opencti'], listKey = 'importFiles', valueKey = 'name', newKey = 'importFiles')
        # Convert list of label objects to list of label names:
        simplify_objectlist(alert_output['opencti'], listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')

        # In case there are several indicators, and since we will only extract
        # one, sort them based on !revoked, score, confidence and lastly
        # expiry:
        indicators = sorted(indicators, key=lambda x: (x['revoked'], -x['x_opencti_score'], -x['confidence'], datetime.strptime(x['valid_until'], '%Y-%m-%dT%H:%M:%S.%fZ') <= datetime.now()))
        alert_output['opencti']['indicator'] = indicators[0]
        # Indicate in the alert that there were multiple indicators:
        alert_output['opencti']['multipleIndicators'] = len(indicators) > 1
        # Generate a link to the indicator:
        alert_output['opencti']['indicator_link'] = url.removesuffix('graphql') + 'dashboard/observations/indicators/{0}'.format(indicators[0]['id'])
        # Simplify object lists for indicator labels and kill chain phases:
        simplify_objectlist(alert_output['opencti']['indicator'], listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')
        simplify_objectlist(alert_output['opencti']['indicator'], listKey = 'killChainPhases', valueKey = 'kill_chain_name', newKey = 'killChainPhases')
        # Remove the original list of objects:
        del alert_output['opencti']['indicators']

        # Add source information to the original alert (naming convention
        # from official VirusTotal integration):
        alert_output['opencti']['source'] = {}
        alert_output['opencti']['source']['alert_id'] = alert['id']
        if 'syscheck' in alert:
            alert_output['opencti']['source']['file'] = alert['syscheck']['path']
            alert_output['opencti']['source']['md5'] = alert['syscheck']['md5_after']
            alert_output['opencti']['source']['sha1'] = alert['syscheck']['sha1_after']
        if 'data' in alert:
            for key in ['in_iface', 'src_ip', 'src_mac', 'src_port', 'dest_ip', 'dst_mac', 'dest_port', 'proto', 'app_proto']:
                if key in alert['data']:
                    alert_output['opencti']['source'][key] = alert['data'][key]
            if 'alert' in alert['data']:
                alert_output['opencti']['source']['alert'] = {}
                for key in ['action', 'category', 'signature', 'signature_id']:
                    if key in alert['data']['alert']:
                        alert_output['opencti']['source']['alert'][key] = alert['data']['alert'][key]

        # Send event, after removing all nulls, empty lists and objects, and
        # empty strings:
        send_event(remove_empties(alert_output), alert['agent'])

if __name__ == '__main__':
    try:
        if len(sys.argv) >= 4:
            debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''), do_log = True)
        else:
            log('Incorrect arguments: {0}'.format(' '.join(sys.argv)))
            sys.exit(1)

        debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'

        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log = True)
        debug(traceback.format_exc(), do_log = True)
        raise
