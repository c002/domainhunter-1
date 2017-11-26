#!/usr/bin/env python3

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import uuid
import sys
import threading
import ipaddress
from multiprocessing import Process, Queue
import MySQLdb
import re

threads = []


def store_record(uuid_child, uuid_parent, fqdn, r_type, value, s_dt, q_dt, r_dt):
    pool_sema.acquire()
    db_o = open_db()

    print("store record:", "Child UUID", uuid_child, "Parent UUID", uuid_parent, fqdn, r_type, value, file=sys.stderr)
    try:

        db_o['cursor'].execute("INSERT INTO " +
                               "    dns_records (uuid, uuid_parent, fqdn, r_type, value, s_dt, q_dt, r_dt) " +
                               "     VALUES     (  %s,          %s,   %s,     %s,    %s,   %s,   %s,   %s)",
                                          (uuid_child, uuid_parent, fqdn, r_type,
                                                                                  value,
                                                           s_dt.strftime('%Y-%m-%d %H:%M:%S'),
                                                                 q_dt.strftime('%Y-%m-%d %H:%M:%S'),
                                                                       r_dt.strftime('%Y-%m-%d %H:%M:%S')))
        db_o['connection'].commit()
    except Exception as inst:
        print("store_record:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)
    pool_sema.release()

def store_no_answer(uuid_child, uuid_parent, fqdn, r_type, reason, s_dt, q_dt, r_dt):
    pool_sema.acquire()
    db_o = open_db()

    print("store No Answer", "Child UUID", uuid_child, "Parent UUID", uuid_parent, fqdn, r_type, reason, file=sys.stderr)
    try:

        db_o['cursor'].execute("INSERT INTO " +
                               "    no_answer(uuid, uuid_parent, fqdn, r_type, reason, s_dt, q_dt, r_dt) " +
                               "      VALUES (  %s,          %s,   %s,     %s,     %s,   %s,   %s,   %s)",
                                       (uuid_child, uuid_parent, fqdn, r_type, reason,
                                                         s_dt.strftime('%Y-%m-%d %H:%M:%S'),
                                                               q_dt.strftime('%Y-%m-%d %H:%M:%S'),
                                                                     r_dt.strftime('%Y-%m-%d %H:%M:%S')))
        db_o['connection'].commit()
    except Exception as inst:
        print("store_no_answer:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)
    pool_sema.release()



def analyse_record(uuid_child, uuid_parent, fqdn, r_type, r_data, s_dt):
    if r_type == 'CNAME':
        uuid_child_child = str(uuid.uuid4())

        # uuid_child is now the parent, uuid_new_child is the new child under the child
        resolve_multi_type(uuid_child_child, uuid_child, str(r_data), s_dt)
    elif r_type == 'MX':
        uuid_child_child = str(uuid.uuid4())

        # uuid_child is now the parent, uuid_new_child is the new child under the child
        resolve_multi_type(uuid_child_child, uuid_child, r_data.exchange, s_dt)

    elif r_type == 'TXT':
        clean_r_data = re.sub(r'^"|"$', '', str(r_data))
        if clean_r_data.startswith('v=spf1'):
            # Found SPFv1 record
            uuid_child_child = str(uuid.uuid4())
            q_dt = datetime.utcnow()
            r_dt = datetime.utcnow()

            print("found SPF record", clean_r_data, file=sys.stderr)

            # Store entire SPF record. The content is a child under this.
            store_record(uuid_child_child, uuid_child, fqdn, 'SPF', clean_r_data, s_dt, q_dt, r_dt)

            print(clean_r_data.split()[-1], file=sys.stderr)
            for elem in clean_r_data.split():
                print(elem, file=sys.stderr)

                # Found an A record in the SPF
                if elem.upper() == 'A':
                    uuid_child_child_child = str(uuid.uuid4())

                    # Store found A record and recurse
                    store_record(uuid_child_child_child, uuid_child_child, fqdn, 'A', '', s_dt, q_dt, r_dt)
                    analyse_record(uuid_child_child_child, uuid_child_child, fqdn, 'A', '', s_dt)

                    # Perhaps recurse fully... but let's not recurse enlessly yet.
                    # resolve_multi_type(uuid_child_child, uuid_child, fqdn, s_dt)

                # Found an AAAA record in the SPF
                if elem.upper() == 'AAAA':
                    uuid_child_child_child = str(uuid.uuid4())

                    # Store found A record and recurse
                    store_record(uuid_child_child_child, uuid_child_child, fqdn, 'AAAA', '', s_dt, q_dt, r_dt)
                    analyse_record(uuid_child_child_child, uuid_child_child, fqdn, 'AAAA', '', s_dt)

                    # Perhaps recurse fully... but let's not recurse enlessly yet.
                    # resolve_multi_type(uuid_child_child, uuid_child, fqdn, s_dt)

                if elem.startswith('include:'):
                    uuid_child_child_child = str(uuid.uuid4())

                    include_data = elem.split(':')[-1]

                    # Found include, must expand this by recursing into the include directory by resolving the TXT.
                    store_record(uuid_child_child_child, uuid_child_child, include_data, 'include', '', s_dt, q_dt, r_dt)
                    analyse_record(uuid_child_child_child, uuid_child_child, include_data, 'FQDN', '', s_dt)

                # Still needs ip4: ip6: and a: and aaaa:



def resolve_r_type(uuid_child, uuid_parent, fqdn, r_type, s_dt):
    answers = None
    try:
        q_dt = datetime.utcnow()
        resolver = dns.resolver.Resolver()
        resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
        resolver.timeout = 20
        resolver.lifetime = 20
        answers = resolver.query(fqdn, r_type)
        r_dt = datetime.utcnow()
        for r_data in answers:
            store_record(uuid_child, uuid_parent, fqdn, r_type, str(r_data), s_dt, q_dt, r_dt)
            analyse_record(uuid_child, uuid_parent, fqdn, r_type, r_data, s_dt)

    except dns.resolver.NXDOMAIN:
        r_dt = datetime.utcnow()
        store_no_answer(uuid_child, uuid_parent, fqdn, r_type, 'nxdomain', s_dt, q_dt, r_dt)
    except dns.exception.Timeout:
        print("Time out reached", file=sys.stderr)
    except dns.resolver.NoAnswer as e:
        r_dt = datetime.utcnow()
        store_no_answer(uuid_child, uuid_parent, fqdn, r_type, 'no answer', s_dt, q_dt, r_dt)
    except dns.resolver.NoMetaqueries:
        r_dt = datetime.utcnow()
        store_no_answer(uuid_child, uuid_parent, fqdn, r_type, 'no metaquery', s_dt, q_dt, r_dt)
    except EOFError:
        print("EOFError", file=sys.stderr)
    except Exception as inst:
        print("DNS Tester: Unknown type of error is", type(inst), inst, file=sys.stderr)


def open_db():
    db_o = {}
    db_o['connection'] = MySQLdb.connect('localhost', 'domainhunter', 'domainhunter42', 'domainhunter');
    db_o['cursor'] = db_o['connection'].cursor()
    return db_o

def close_db(db_o):
    db_o['cursor'].close()
    db_o['connection'].close()

def resolve_multi_type(uuid_parent, fqdn, s_dt):
    # types = ['A', 'AAAA', 'CAA', 'RRSIG', 'CNAME', 'MX', 'TXT', 'PTR', 'NS', 'NAPTR', 'SOA', 'SRV', 'SSHFP', 'TLSA', 'ANY']
    types = ['A', 'AAAA', 'CAA', 'RRSIG', 'CNAME', 'MX', 'TXT', 'PTR', 'NS', 'NAPTR', 'SOA', 'SRV', 'SSHFP']
    for i in types:
        uuid_child = str(uuid.uuid4())
        resolve_r_type(uuid_child, uuid_parent, fqdn, i, s_dt)

def resolve_multi_sub_domains_per_thread(uuid_parent, fqdn, s_dt):
    try:
        t = threading.Thread(target=resolve_multi_type, args=(uuid_parent, fqdn, s_dt,))
        threads.append(t)
        t.start()
    except:
        print("Error: unable to start new thread!", uuid, fqdn, i, file=sys.stderr)

def resolve_multi_sub_domains(uuid_main, base_fqdn, s_dt):

    resolve_multi_sub_domains_per_thread(uuid_main, base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'www'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'login'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'shell'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'account'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'accounts'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'ftp'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'imap'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'smtp'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'pop'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'pop3'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'mail'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'cloud'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'cdn'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'voip'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'autodiscover'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'proxy'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'sip'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'sips'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'pbx'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'monitor'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'monitoring'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'wiki'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'citrix'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'vpn'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'remote'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'mobile'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'cups'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'printer'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'ssh'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, '_dmarc'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'dmarc'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, '_spf'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'spf'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'test'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'testing'+'.'+base_fqdn, s_dt)
    resolve_multi_sub_domains_per_thread(uuid_main, 'acc'+'.'+base_fqdn, s_dt)

    # Rejoin threads before program ends
    for t in threads:
        t.join()


def main_child(uuid_main, base_fqdn, s_dt):
    resolve_multi_sub_domains(uuid_main, base_fqdn, s_dt)

### MAIN ###
if len(sys.argv) != 2:
    print("Please provide one domain name only")
    sys.exit(1)

base_fqdn = sys.argv[1]

uuid_main = str(uuid.uuid4())
s_dt = datetime.utcnow()
maxconnections = 10
pool_sema = threading.BoundedSemaphore(value=maxconnections)

print(str(uuid_main), "for a search on base FQDN", base_fqdn, "started at", str(s_dt), file=sys.stdout)
p = Process(target=main_child, args=(uuid_main, base_fqdn, s_dt))
p.start()

