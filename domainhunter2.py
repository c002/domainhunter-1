#!/usr/bin/env python3

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import uuid
import sys
import os
import threading
import ipaddress
from multiprocessing import Process, Queue, JoinableQueue
import warnings
from ipwhois.net import Net
from ipwhois.asn import IPASN
from pprint import pprint
import re
import sqlite3
from urllib.request import urlopen
import json


warnings.filterwarnings('ignore')

q = JoinableQueue()
workload = []


# PATH = "/var/www/domainhunter.koeroo.net/"
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'


def open_db():
    db_o = {}
    try:
        db_o['connection'] = sqlite3.connect(PATH + 'db/domainhunter2.db')
        db_o['cursor'] = db_o['connection'].cursor()
    except:
        sys.exit(1)

    return db_o

def create_db():
    try:
        db_o = open_db()

        # Create the tables
        db_o['connection'].execute('''CREATE TABLE domainhunts (uuid_hunt TEXT, fqdn TEXT, s_dt DATETIME)''')
        db_o['connection'].execute('''CREATE TABLE dns (uuid_dns TEXT, uuid_parent TEXT, fqdn TEXT, r_type TEXT, res TEXT)''')
        db_o['connection'].execute('''CREATE TABLE asn (uuid_asn TEXT, uuid_parent TEXT,
                                                        asn TEXT,
                                                        asn_description TEXT,
                                                        asn_date TEXT,
                                                        asn_registry TEXT,
                                                        asn_country_code TEXT,
                                                        asn_cidr TEXT
                                                        )''')
        db_o['connection'].execute('''CREATE TABLE dns_to_asn (uuid_hunt TEXT, uuid_dns TEXT, uuid_asn TEXT)''')

        # Commit !
        db_o['connection'].commit()
    except Exception as inst:
        print("store_main_domain:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)


def store_dns_to_asn(uuid_hunt, uuid_dns, uuid_asn):
    print("store_dns_to_asn", uuid_hunt, uuid_dns, uuid_asn, file=sys.stderr)

    try:
        db_o = open_db()
        db_o['cursor'].execute("INSERT INTO " +
                               "    dns_to_asn (uuid_hunt, uuid_dns, uuid_asn) " +
                               "         VALUES (       ?,        ?,        ?)",
                              (uuid_hunt, uuid_dns, uuid_asn,))
        db_o['connection'].commit()
        db_o['connection'].close()
    except Exception as inst:
        print("store_dns_to_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)


def store_hunt_domain(uuid_hunt, fqdn, s_dt):
    print("store_hunt_domain", uuid_hunt, fqdn, file=sys.stderr)

    try:
        db_o = open_db()
        db_o['cursor'].execute("INSERT INTO " +
                               "    domainhunts (uuid_hunt, fqdn, s_dt) " +
                               "         VALUES (        ?,    ?,    ?)",
                               (uuid_hunt,
                                fqdn,
                                s_dt.strftime('%Y-%m-%d %H:%M:%S'),))
        db_o['connection'].commit()
        db_o['connection'].close()
    except Exception as inst:
        print("store_hunt_domain:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)


def store_dns(uuid_child, uuid_parent, fqdn, r_type, res):
    print("store_dns", uuid_child, uuid_parent, fqdn, r_type, res, file=sys.stderr)

    try:
        db_o = open_db()
        db_o['cursor'].execute("INSERT INTO " +
                               "            dns (uuid_dns, uuid_parent, fqdn, r_type, res) " +
                               "     VALUES (            ?,           ?,    ?,      ?,  ?)",
                               (uuid_child,
                                uuid_parent,
                                fqdn,
                                r_type,
                                res,))
        db_o['connection'].commit()
        db_o['connection'].close()
    except Exception as inst:
        print("store_dns:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

def store_asn(uuid_child, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr):
    print("store_asn", uuid_child, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr, file=sys.stderr)
    try:
        db_o = open_db()
        db_o['cursor'].execute("INSERT INTO " +
                               "            asn (uuid_asn,      uuid_parent,              asn, asn_description, " +
                               "                 asn_date,     asn_registry, asn_country_code,        asn_cidr) " +
                               "     VALUES (           ?,                ?,                ?,               ?,  " +
                               "                        ?,                ?,                ?,               ?)",
                               (uuid_child,
                                uuid_parent,
                                asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr,))
        db_o['connection'].commit()
        db_o['connection'].close()
    except Exception as inst:
        print("store_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)


def fetch_asn_uuid(asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr):
    db_o = open_db()
    uuid_asn = None

    print("fetch_asn_uuid", asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr, file=sys.stderr)
    try:
        db_o['cursor'].execute("SELECT uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr " +
                               "  FROM asn " +
                               " WHERE asn = ? " +
                               "   AND asn_description = ? " +
                               "   AND asn_date = ? " +
                               "   AND asn_registry = ? " +
                               "   AND asn_country_code = ? " +
                               "   AND asn_cidr = ?",
                               (asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr,))

    except Exception as inst:
        print("fetch_asn_uuid", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr) in db_o['cursor']:
            print ("fetch_asn_uuid", uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr, file=sys.stderr)

    except Exception as inst:
        print("fetch_asn_uuid", "Unknown type of error is:", type(inst), inst, file=sys.stderr)


    db_o['connection'].close()
    return uuid_asn


def analyse_record2(uuid_child, uuid_parent, k, key_type, val, val_type, status, reason, dt, last_key_is_fqdn):
    try:
        # Remember where we came from. Required for SPF1 and DMARC
        if key_type == 'FQDN':
            last_key_is_fqdn = k

        if val_type == 'FQDN':
            # Need to resolve this FQDN again, but with the current uuid_child as its parent
            q.put((uuid_child, val, s_dt))


        ### Logic starts here

        # Planned exit or stop condition
        if  (key_type == 'FQDN' and (val_type == 'CAA' or val_type == 'SOA')) or \
            (key_type == 'DNS_R_TYPE' and val_type == 'SPF1'):
            print ("analyse_record2", "Explicit final",
                   'key_type', key_type,
                   'key', k,
                   'val_type', val_type,
                   'value', val,
                   file=sys.stderr)

        elif key_type == 'FQDN' and val_type == 'NS':
            # The NS value is an FQDN per default
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            q.put((uuid_child, val, s_dt))

        elif key_type == 'FQDN' and val_type == 'CNAME':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            d = str(val)[:-1]
            q.put((uuid_child, d, s_dt))

        elif key_type == 'FQDN' and val_type == 'MX':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            priority = val.split()[0]
            exchange = val.split()[1][:-1]
            q.put((uuid_child, exchange, s_dt))

        elif key_type == 'SPF1' and val_type == "INCLUDE":
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            q.put((uuid_child, val, s_dt))

        elif val_type == 'TXT':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            clean_value = re.sub(r'^"|"$', '', str(val))

            # TXT record is already stored, see what's in the TXT and that is
            # your next child node
            if clean_value.lower().startswith('v=spf1'):
                # Found SPFv1 record
                analyse_record2(uuid_child, uuid_parent,
                                val,
                                val_type,
                                clean_value,
                                "SPF1",
                                "ANALYSED", "", dt,
                                last_key_is_fqdn)

        elif val_type == 'SPF1':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            for elem in val.split():
                print(elem, file=sys.stderr)

                # Found an A record in the SPF
                if elem.upper() == 'A' or elem.upper() == 'AAAA':
                    print ("analyse_record2",
                           "undecided what to do to avoid an endless recursion",
                           'key_type', key_type,
                           'key', k,
                           'val_type', val_type,
                           'value', val,
                           'elem',
                           elem,
                           'last_key_is_fqdn',
                           last_key_is_fqdn,
                           file=sys.stderr)


                    # Continue analysing
                    analyse_record2(uuid_child, uuid_parent,
                                    elem.upper(),
                                    "DNS_R_TYPE",
                                    val,
                                    val_type,
                                    "ANALYSED", "", dt,
                                    last_key_is_fqdn)

                # Found an INCLUDE statement in the SPF
                if elem.lower().startswith('include:'):
                    # Continue analysing
                    analyse_record2(uuid_child, uuid_parent,
                                    val,
                                    val_type,
                                    elem.split(':')[-1],
                                    "INCLUDE",
                                    "ANALYSED", "", dt,
                                    last_key_is_fqdn)

                # Found an IPv4 statement in the SPF
                if elem.lower().startswith('ip4:'):
                    # Continue analysing
                    analyse_record2(uuid_child, uuid_parent,
                                    val,
                                    val_type,
                                    elem.split(':')[-1],
                                    "IPV4_CIDR",
                                    "ANALYSED", "", dt,
                                    last_key_is_fqdn)

                # Found an IPv6 statement in the SPF
                if elem.lower().startswith('ip6:'):
                    # Continue analysing
                    analyse_record2(uuid_child, uuid_parent,
                                    val,
                                    val_type,
                                    elem.split(':')[-1],
                                    "IPV6_CIDR",
                                    "ANALYSED", "", dt,
                                    last_key_is_fqdn)


#        elif key_type == 'SPF1' and val_type == "DNS_R_TYPE":
#            if val == 'A' or val == 'AAAA':
#                analyse_record2(uuid_child, uuid_parent,
#                                val,
#                                val_type,
#                                last_key_is_fqdn,
#                                "FQDN",
#                                "ANALYSED", "", dt,
#                                last_key_is_fqdn)


        # A, AAAA or results from SPF1 and other records with an IP address in it
        ### Error handling CIDR notation -
        ### elif val_type == 'A' or val_type == 'AAAA' or val_type == "IPV4_CIDR" or val_type == "IPV6_CIDR":
        elif val_type == 'A' or val_type == 'AAAA':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            uuid_child_child = str(uuid.uuid4())

            # Take A or AAAA value to resolve as part of an AS plus AS info
            asn_result = analyse_asn(val)

            uuid_asn = fetch_asn_uuid(asn_result['asn'], asn_result['asn_description'],
                                      asn_result['asn_date'], asn_result['asn_registry'],
                                      asn_result['asn_country_code'], asn_result['asn_cidr'])
            if uuid_asn is None:
                store_asn (uuid_child_child, uuid_child, asn_result['asn'], asn_result['asn_description'],
                                                         asn_result['asn_date'], asn_result['asn_registry'],
                                                         asn_result['asn_country_code'], asn_result['asn_cidr'])
                uuid_asn = fetch_asn_uuid(asn_result['asn'], asn_result['asn_description'],
                                          asn_result['asn_date'], asn_result['asn_registry'],
                                          asn_result['asn_country_code'], asn_result['asn_cidr'])

            # Map DNS record (here an A or AAAA) to ASN
            store_dns_to_asn(uuid_hunt, uuid_child, uuid_asn)

        else:
            print ("analyse_record2", "Final reached",
                   'key_type', key_type,
                   'key', k,
                   'val_type', val_type,
                   'value', val,
                   file=sys.stderr)

    except Exception as inst:
        print("analyse_record2", "Error:", type(inst), inst, 'key_type', key_type, 'val_type', val_type, file=sys.stderr)



def analyse_asn(ip):
    net = Net(ip)
    obj = IPASN(net)
    results = obj.lookup()

    print (results, file=sys.stderr)
    return results

    s = str(results)
    s = s.replace('\',', '\n')
    s = s.replace('{', '')
    s = s.replace('}', '')
    s = s.replace('\'', '')

    q_dt = datetime.utcnow()
    r_dt = datetime.utcnow()
    #store_record(uuid_child, uuid_parent, ip, 'ASN', s, s_dt, q_dt, r_dt)
    # {'asn_description': 'NIKHEF FOM-Nikhef, NL', 'asn_cidr': '192.16.199.0/24', 'asn_registry': 'ripencc', 'asn': '1104', 'asn_country_code': 'NL', 'asn_date': '1986-11-07'}
    # {'asn': '15169', 'asn_date': '2008-09-30', 'asn_description': 'GOOGLE - Google LLC, US', 'asn_cidr': '2404:6800:4003::/48', 'asn_registry': 'apnic', 'asn_country_code': 'AU'}
    # {'asn': '15169', 'asn_date': '2007-03-13', 'asn_description': 'GOOGLE - Google LLC, US', 'asn_cidr': '74.125.200.0/24', 'asn_registry': 'arin', 'asn_country_code': 'US'}


#    elif r_type == 'A':
#        # Assume A record is already stored, only analyse deeper.
#        print("analyse A", str(r_data), file=sys.stderr)
#
#        try:
#            # Search Shodan
#            results = api.search(str(r_data))
#
#            # Show the results
#            print('Results found: %s' % results['total'], file=sys.stderr)
#            for result in results['matches']:
#                print('IP: %s' % result['ip_str'], file=sys.stderr)
#                print(result['data'], file=sys.stderr)
#                print('', file=sys.stderr)
#        except shodan.APIError as e:
#            print('Error: %s' % e, file=sys.stderr)
#
#        #store_record(uuid_child, uuid_parent, fqdn, r_type, str(r_data), s_dt, q_dt, r_dt)



def resolve_r_type(uuid_parent, fqdn, r_type, s_dt):
    answers = None
    q_dt = datetime.utcnow()
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
        resolver.nameservers=['127.0.0.1']
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.query(fqdn, r_type)
        for r_data in answers:
            uuid_child = str(uuid.uuid4())
            store_dns      (uuid_child, uuid_parent, fqdn, r_type, str(r_data))
            analyse_record2(uuid_child, uuid_parent, fqdn, "FQDN", str(r_data), r_type, "RESOLVED", "", q_dt, "")
#            analyse_record(uuid_child, uuid_parent, fqdn, r_type, r_data, s_dt)

    except dns.resolver.NXDOMAIN:
        # Ignore the NXDOMAINs
        pass
    except dns.exception.Timeout:
        print("Domainhunter: Time out reached", file=sys.stderr)
        uuid_child = str(uuid.uuid4())
    except dns.resolver.NoAnswer as e:
        uuid_child = str(uuid.uuid4())
    except dns.resolver.NoMetaqueries:
        uuid_child = str(uuid.uuid4())
    except EOFError:
        print("Domainhunter: EOFError", file=sys.stderr)
    except Exception as inst:
        print("Domainhunter: Unknown type of error is", type(inst), inst, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)


def resolve_multi_type(uuid_parent, fqdn, s_dt):
    # types = ['A', 'AAAA', 'CAA', 'RRSIG', 'CNAME', 'MX', 'TXT', 'PTR', 'NS', 'NAPTR', 'SOA', 'SRV', 'SSHFP', 'TLSA', 'ANY']
    types = ['A', 'AAAA', 'CAA', 'RRSIG', 'CNAME', 'MX', 'TXT', 'PTR', 'NS', 'NAPTR', 'SOA', 'SRV', 'SSHFP', 'TLSA']
    for t in types:
        resolve_r_type(uuid_parent, fqdn, t, s_dt)


def worker():
    while True:
        uuid_parent, fqdn, s_dt = q.get()
        print ("Worker:", uuid_parent, fqdn, file=sys.stderr)
        resolve_multi_type(uuid_parent, fqdn, s_dt)
        q.task_done()

def add_ct_fqdn(uuid_hunt, base_fqdn, s_dt):
    html = urlopen("https://certspotter.com/api/v0/certs?expired=false&duplicate=false&domain=" + base_fqdn)
    s = html.read()
    res = json.loads(s.decode('utf8'))

    for ct_cert in res:
        for fqdn in ct_cert['dns_names']:
            workload.append(fqdn)



def resolve_multi_sub_domains(uuid_hunt, base_fqdn, s_dt):
    # Start concurrent worker threads
    num_worker_threads = 50
    for i in range(num_worker_threads):
         t = threading.Thread(target=worker)
         t.daemon = True
         t.start()

    # Add the base
    workload.append(base_fqdn)

    # Add static list
    temp = open(PATH + 'research.list','r').read().splitlines()
    for prefix in temp:
        workload.append(prefix + '.' + base_fqdn)

    # Use certificate transparency
    add_ct_fqdn(uuid_hunt, base_fqdn, s_dt)

    # Total workload
    for fqdn in workload:
        print(fqdn)
        q.put((uuid_hunt, fqdn, s_dt))

    q.join()       # block until all tasks are done



### MAIN ###
if len(sys.argv) != 2:
    print("Please provide one domain name only")
    sys.exit(1)

# Create the database, incl tables
create_db()

# Target to hunt
base_fqdn = sys.argv[1]

# Generate UUID for this hunt
uuid_hunt = str(uuid.uuid4())
s_dt = datetime.utcnow()

# Generic storage of this try.
store_hunt_domain(uuid_hunt, base_fqdn, s_dt)


print(str(uuid_hunt), "for a search on base FQDN", base_fqdn, "started at", str(s_dt), file=sys.stdout)

# Start here...
resolve_multi_sub_domains(uuid_hunt, base_fqdn, s_dt)
