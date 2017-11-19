#!/usr/bin/env python3
# encoding: utf-8
'''
Gandi v5 LiveDNS - DynDNS Update via REST API and CURL/requests

@author: tehem (original author cave)
License GPLv3
https://www.gnu.org/licenses/gpl-3.0.html

Created on 13 Aug 2017 by cave
Updated on 19 Nov 2017 by tehem
http://doc.livedns.gandi.net/ 
http://doc.livedns.gandi.net/#api-endpoint -> https://dns.beta.gandi.net/api/v5/
'''
import collections
import requests
import json
import random
import re
import time
import config
import argparse

import logging as log
log.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s', level=log.DEBUG)

# matches all IPv4 addresses, including invalid ones. we look for
# multiple-provider agreement before returning an IP.
IP_ADDRESS_REGEX = re.compile('\d{1,3}(?:\.\d{1,3}){3}')

def get_external_ip_from_url(url):
  '''Get all the IP addresses found at a given URL.'''

  # open the website, download its data, and return all IP strings found
  # we want to respect some site's filtering on User-Agent.
  data = requests.get(url)
  addys = IP_ADDRESS_REGEX.findall(data.text)
  return addys

def get_external_ip(attempts=100, threshold=3):
  '''Return our current external IP address, or None if there was an error.'''

  # load the list of IP address providers
  providers = load_providers()

  # we want several different providers to agree on the address, otherwise we
  # need to keep trying to get agreement. this prevents picking up 'addresses'
  # that are really just strings of four dot-delimited numbers.
  ip_counts = collections.Counter()

  # the providers we're round-robining from
  current_providers = []

  while attempts > 0:
    # reduce our attempt count every time, to ensure we'll exit eventually
    attempts -= 1

    # randomly shuffle the providers list when it's empty so we can round-robin
    # from all the providers. also reset the counts, since double-counting
    # results from the same providers might result in false-positives.
    if not current_providers:
      current_providers = providers[:]
      random.shuffle(current_providers)
      ip_counts = collections.Counter()

    # get the provider we'll try this time
    provider = current_providers.pop()

    try:
      addys = get_external_ip_from_url(provider)

      # add a single address to the counter randomly to help prevent false
      # positives. we don't add all the found addresses to guard against adding
      # multiple false positives for the same site. taking a single random
      # address and then checking it against the other sites is safer. what are
      # the chances that several sites will return the same false-positive
      # number?
      if addys:
        ip = random.choice(addys)
        ip_counts.update({ ip: 1 })
        log.debug('Got IP from provider %s: %s', provider, ip)

      # check for agreeing IP addresses, and return the first address that meets
      # or exceeds the count threshold.
      for ip, count in ip_counts.most_common():
        if count < threshold:
          break
        return ip

    except Exception as e:
      log.warning('Error getting external IP address from %s: %s', provider, e)

      # sleep a bit after errors, in case it's a general network error. if it
      # is, hopefully this will give some time for the network to come back up.
      time.sleep(0.1 + random.random() * 2)

  log.warning('Failed to get an external IP address after %d attempts!', attempts)

def load_providers():
  '''Load the providers file as a de-duplicated and normalized list of URLs.'''
  with open('/volume1/backup/uranus/providers.json') as f:
    providers = json.load(f)['providers']
  return list(set([p.strip() for p in providers]))

def test_providers():
  '''Test all IP providers and log the IPs they return.'''

  for provider in load_providers():
    log.debug('IPs found at %s:', provider)

    try:
      for ip in get_external_ip_from_url(provider):
        log.debug('  %s', ip)
    except Exception as e:
      log.warning('Error getting external IP address from %s: %s', provider, e)

def get_uuid():
    ''' 
    find out ZONE UUID from domain
    Info on domain "DOMAIN"
    GET /domains/<DOMAIN>:
        
    '''
    url = config.api_endpoint + '/domains/' + config.domain
    u = requests.get(url, headers={"X-Api-Key":config.api_secret})
    json_object = u.json()
    if u.status_code == 200:
        return json_object['zone_uuid']
    else:
        log.debug('Error: HTTP Status Code ', u.status_code, 'when trying to get Zone UUID')
        log.debug(json_object['message'])
        exit()

def get_dnsip(uuid):
    ''' find out IP from first Subdomain DNS-Record
    List all records with name "NAME" and type "TYPE" in the zone UUID
    GET /zones/<UUID>/records/<NAME>/<TYPE>:
    
    The first subdomain from config.subdomain will be used to get   
    the actual DNS Record IP
    '''

    url = config.api_endpoint+ '/zones/' + uuid + '/records/' + config.subdomains[0] + '/A'
    headers = {"X-Api-Key":config.api_secret}
    u = requests.get(url, headers=headers)
    if u.status_code == 200:
        jsonResponse = u.json()
        dnsIp = jsonResponse["rrset_values"][0];
        log.debug('Checking IP from DNS Record %s: %s', config.subdomains[0], dnsIp)
        return dnsIp
    else:
        log.debug('Error: HTTP Status Code ', u.status_code, 'when trying to get IP from subdomain', config.subdomains[0])
        log.debug(json_object['message'])
        exit()

def update_records(uuid, dynIP, subdomain):
    ''' update DNS Records for Subdomains 
        Change the "NAME"/"TYPE" record from the zone UUID
        PUT /zones/<UUID>/records/<NAME>/<TYPE>:
        curl -X PUT -H "Content-Type: application/json" \
                    -H 'X-Api-Key: XXX' \
                    -d '{"rrset_ttl": 10800,
                         "rrset_values": ["<VALUE>"]}' \
                    https://dns.beta.gandi.net/api/v5/zones/<UUID>/records/<NAME>/<TYPE>
    '''
    url = config.api_endpoint+ '/zones/' + uuid + '/records/' + subdomain + '/A'
    payload = {"rrset_ttl": config.ttl, "rrset_values": [dynIP]}
    headers = {"Content-Type": "application/json", "X-Api-Key":config.api_secret}
    u = requests.put(url, data=json.dumps(payload), headers=headers)
    json_object = u.json()

    if u.status_code == 201:
        log.debug('Status Code:', u.status_code, ',', json_object['message'], ', IP updated for', subdomain)
        return True
    else:
        log.debug('Error: HTTP Status Code ', u.status_code, 'when trying to update IP from subdomain', subdomain)
        log.debug(json_object['message'])
        exit()

def main(force_update):
	
    #get zone ID from Account
    uuid = get_uuid()
   
     # see if the record's IP differs from ours
    log.debug('Getting external IP...')
    dynIP = get_external_ip()
	
    log.debug('External IP is: %s', dynIP)
	
	# make sure we actually got the external IP
    if dynIP is None:
      log.fatal('Could not get external IP.')
      sys.exit(2)
    
    log.debug('Getting DNS record IP...')
    dnsIP = get_dnsip(uuid)
    
    log.debug('DNS record IP is: %s', dnsIP)
	
    if force_update:
        log.debug("Going to update/create the DNS Records for the subdomains")
        for sub in config.subdomains:
            update_records(uuid, dynIP, sub)
    else:
        if dynIP == dnsIP:
            log.debug("IP Address Match - no further action")
        else:
            lgo.debug("IP Address Mismatch - going to update the DNS Records for the subdomains with new IP", dynIP)
            for sub in config.subdomains:
                update_records(uuid, dynIP, sub)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--force', help="force an update/create", action="store_true")
    args = parser.parse_args()
        
        
    main(args.force)
