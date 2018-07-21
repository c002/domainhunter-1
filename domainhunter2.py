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
from pygraphviz import *


class Workload:
    mem_db = {}

    def __init__(self, base_fqdn, uuid_hunt=None):
        self.base_fqdn = base_fqdn

        self.initialize()
        self.s_dt = datetime.utcnow()
        if uuid_hunt is None:
            self.uuid_hunt = str(uuid.uuid4())
        else:
            self.uuid_hunt = uuid_hunt

    def initialize(self):
        self.mem_db['connection'] = sqlite3.connect(':memory:')
        self.mem_db['cursor'] = self.mem_db['connection'].cursor()
        self.mem_db['connection'].execute('''CREATE TABLE fqdns (uuid_fqdn, fqdn TEXT, status TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr (uuid_rr TEXT, fqdn TEXT, r_type TEXT, value TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE asn (uuid_asn TEXT, asn TEXT, asn_description TEXT,
                                                               asn_date TEXT, asn_registry TEXT,
                                                               asn_country_code TEXT, asn_cidr TEXT
                                                              )''')
        self.mem_db['connection'].execute('''CREATE TABLE ip (uuid_ip TEXT, ip TEXT, version TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE ip2asn (uuid_ip TEXT, uuid_asn TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr_parent_child (uuid_parent TEXT, uuid_child TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr_to_ip (uuid_rr TEXT, uuid_ip TEXT)''')

    def add_dns_rr_to_ip(self, uuid_rr, uuid_ip):
        sql = ' '.join(["INSERT INTO dns_rr_to_ip",
                                    "(uuid_rr, uuid_ip)"
                             "VALUES (:uuid_rr, :uuid_ip)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_rr":uuid_rr,
                                      "uuid_ip":uuid_ip})
        return True

    def add_dns_rr_parent_child(self, uuid_parent, uuid_child):
        sql = ' '.join(["INSERT INTO dns_rr_parent_child",
                                    "(uuid_parent, uuid_child)",
                             "VALUES (:uuid_parent, :uuid_child)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_parent":uuid_parent,
                                      "uuid_child":uuid_child})
        return True

    def get_dns_rr_parent_child(self):
        dns_rr_parent_child = []
        sql = ' '.join(["SELECT uuid_parent, uuid_child",
                          "FROM dns_rr_parent_child"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_parent, uuid_child) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_parent'] = uuid_parent 
            rec['uuid_child'] = uuid_child
            dns_rr_parent_child.append(rec)
        return dns_rr_parent_child

    def add_fqdn(self, fqdn):
        # Status: "todo", "processing", "done"
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO fqdns",
                                    "(uuid_fqdn, fqdn, status)",
                             "VALUES (:uuid_fqdn, :fqdn, :status)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_fqdn":u,
                                       "fqdn": fqdn,
                                       "status": "todo"})
        return u

    def add_dns_rr(self, fqdn, r_type, value):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO dns_rr",
                                    "(uuid_rr, fqdn, r_type, value)",
                             "VALUES (:uuid_rr, :fqdn, :r_type, :value)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_rr":u,
                                       "fqdn":fqdn,
                                       "r_type": r_type,
                                       "value": value})
        return u

    def add_asn(self, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO asn",
                                   "(uuid_asn, asn, asn_description,",
                                    "asn_date, asn_registry, asn_country_code,",
                                    "asn_cidr)",
                            "VALUES (:uuid_asn, :asn, :asn_description,",
                                    ":asn_date, :asn_registry, :asn_country_code,",
                                    ":asn_cidr)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_asn":u,
                                      "asn":asn,
                                      "asn_description":asn_description,
                                      "asn_date":asn_date,
                                      "asn_registry":asn_registry,
                                      "asn_country_code":asn_country_code,
                                      "asn_cidr":asn_cidr})
        return u

    def count_asn_by_asn_and_asn_cidr(self, c_asn, c_asn_cidr):
        sql = ' '.join(["SELECT count(*)"
                          "FROM asn",
                         "WHERE asn = :asn",
                           "AND asn_cidr = :asn_cidr"])
        self.mem_db['cursor'].execute(sql,
                                      {"asn":c_asn, "asn_cidr":c_asn_cidr})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def get_asn_by_asn_and_asn_cidr(self, c_asn, c_asn_cidr):
        sql = ' '.join(["SELECT uuid_asn, asn, asn_description,",
                               "asn_date, asn_registry, asn_country_code,",
                               "asn_cidr",
                          "FROM asn",
                         "WHERE asn = :asn",
                           "AND asn_cidr = :asn_cidr"])
        self.mem_db['cursor'].execute(sql,
                                      {"asn":c_asn, "asn_cidr":c_asn_cidr})
        for (uuid_asn, asn, asn_description, asn_date, 
             asn_registry, asn_country_code, asn_cidr) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_asn'] = uuid_asn
            rec['asn'] = asn
            rec['asn_description'] = asn_description
            rec['asn_date'] = asn_date
            rec['asn_registry'] = asn_registry
            rec['asn_country_code'] = asn_country_code
            rec['asn_cidr'] = asn_cidr
            # Only get the first, yes, indenting matters
            return rec

    def add_ip(self, ip, version):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO ip (uuid_ip, ip, version)",
                                "VALUES (:uuid_ip, :ip, :version)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_ip":u, "ip":ip, "version":version})
        return u

    def count_ip_by_ip(self, c_ip):
        sql = ' '.join(["SELECT count(ip)",
                          "FROM ip",
                         "WHERE ip = :ip"])
        self.mem_db['cursor'].execute(sql,
                                      {"ip":c_ip})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def get_ip_by_ip(self, g_ip):
        sql = ' '.join(["SELECT uuid_ip, ip, version",
                          "FROM ip",
                         "WHERE ip = :ip"])
        self.mem_db['cursor'].execute(sql,
                                      {"ip":g_ip})
        for (uuid_ip, ip, version) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['ip'] = ip
            rec['version'] = version
            # Only get the first, yes, indenting matters
            return rec

    def add_ip2asn(self, uuid_ip, uuid_asn):
        sql = ' '.join(["INSERT INTO ip2asn (uuid_ip, uuid_asn)",
                                    "VALUES (:uuid_ip, :uuid_asn)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_ip":uuid_ip, "uuid_asn":uuid_asn})
        return True

    def get_dns_rr(self):
        all_dns_rr = []
        sql = ' '.join(["SELECT uuid_rr, fqdn, r_type, value",
                          "FROM dns_rr"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_rr, fqdn, r_type, value) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_rr'] = uuid_rr
            rec['fqdn'] = fqdn
            rec['r_type'] = r_type
            rec['value'] = value
            all_dns_rr.append(rec)
        return all_dns_rr

    def get_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        sql = ' '.join(["SELECT uuid_rr, fqdn, r_type, value",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn, "r_type":g_r_type})
        for (uuid_rr, fqdn, r_type, value) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_rr'] = uuid_rr
            rec['fqdn'] = fqdn
            rec['r_type'] = r_type
            rec['value'] = value
        # Risky return, only the last record... could be more!
        return rec

    def count_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        sql = ' '.join(["SELECT count(*)",
                          "FROM dns_rr",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn, "r_type":g_r_type})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def get_fqdns_not_done(self):
        fqdns = []
        sql = ' '.join(["SELECT fqdn",
                          "FROM fqdns",
                         "WHERE status <> :status"])
        self.mem_db['cursor'].execute(sql,
                                      {"status":"done"})
        for (fqdn,) in self.mem_db['cursor']:
            fqdns.append(fqdn)

        return fqdns

    def get_fqdns_by_fqdn(self, g_fqdn):
        records = []
        sql = ' '.join(["SELECT uuid_fqdn, fqdn, status",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn})
        for (uuid_fqdn, fqdn, status) in self.mem_db['cursor']:
            rec = {}
            rec['uuid'] = uuid_fqdn
            rec['fqdn'] = fqdn
            rec['status'] = status
            records.append(rec)
        return records

    def get_fqdns_by_status(self, g_status, limit=0):
        records = []
        sql = ' '.join(["SELECT fqdn, status ",
                        "  FROM fqdns",
                        " WHERE status = ? "])
        if limit != 0:
            sql = ' '.join([sql, "LIMIT", str(limit)])

        self.mem_db['cursor'].execute(sql, (g_status,))
        for (fqdn, status) in self.mem_db['cursor']:
            rec = {}
            rec['fqdn'] = fqdn
            rec['status'] = status
            records.append(rec)
        return records

    def update_fqdns_status_by_fqdn(self, u_fqdn, u_status):
        records = []
        sql = ' '.join(["UPDATE fqdns",
                           "SET status = :status",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql, 
                                      {"fqdn": u_fqdn,
                                       "status": u_status})
        return True

    def count_fqdns_by_fqdn(self, c_fqdn):
        sql = ' '.join(["SELECT count(fqdn)",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":c_fqdn})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def count_fqdns_by_status(self, c_status):
        sql = ' '.join(["SELECT count(status)",
                          "FROM fqdns",
                         "WHERE status = :status"])
        self.mem_db['cursor'].execute(sql,
                                      {"status":c_status})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def plot(self):
        self.MainGraph.add_node(self.uuid_hunt, style='filled', color='blue', fontcolor='white', 
                                           label="Main search domain is:\n" + self.base_fqdn)

        # Plot the FQDN with RR results and tie that to the main node
        all_dns_rr = self.get_dns_rr()
        for rec in all_dns_rr:
            # Color by RR type
            if rec['r_type'] == "CAA":
                color = 'yellow'
                fontcolor = 'black'
            elif rec['r_type'] == "NS":
                color = 'darkgoldenrod1'
                fontcolor = 'blue'
            elif rec['r_type'] == "MX":
                color = 'orange'
                fontcolor = 'blue'
            elif rec['r_type'] == "SOA":
                color = 'black'
                fontcolor = 'white'
            elif rec['r_type'] == "A":
                color = 'red'
                fontcolor = 'white'
            elif rec['r_type'] == "AAAA":
                color = 'crimson'
                fontcolor = 'white'
            elif rec['r_type'] == "CNAME":
                color = 'gray40'
                fontcolor = 'white'
            elif rec['r_type'] == "TXT":
                color = 'darkviolet'
                fontcolor = 'white'
            else:
                color = 'red'
                fontcolor = 'black'

            # Plot all the nodes
            self.MainGraph.add_node(rec['uuid_rr'], style='filled', 
                                                    color=color, 
                                                    fontcolor=fontcolor, 
                                    label=rec['fqdn'] + "\n" + rec['r_type'] + "\n" + rec['value'])

        # Plot the DNS RR Type linkages
        all_dns_rr_parent_child = self.get_dns_rr_parent_child()
        for rec in all_dns_rr_parent_child:
            # Link up node
            self.MainGraph.add_edge(rec['uuid_parent'], rec['uuid_child'])


    def draw(self, destination):
        # Init graphviz
        self.MainGraph = AGraph(overlap=False,rankdir="LR")

        # Plot the map
        self.plot()

        # Finish lay-out and write the graph
        self.MainGraph.layout()
        self.MainGraph.draw(destination, prog='dot')


#print("add"
#w.add('fqdn1')
#w.add('fqdn2')
#w.add('fqdn3')
#w.add('fqdn4')
#
#print("get")
#print(w.get('fqdn1'))
#
#print("get_by_status")
#print(w.get_by_status('test'))
#print(w.get_by_status('todo'))
#print(w.get_by_status('todo', 1))
#
#print("counts")
#print(w.count_status('todo'))
#print(w.count_status('finished'))
#
#print("update")
#w.update_fqdn('fqdn1', 'finished')
#print(w.count_status('todo'))
#print(w.count_status('finished'))


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
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val)


        # Planned exit or stop condition
        if  (key_type == 'FQDN' and (val_type == 'CAA' or val_type == 'SOA')) or \
            (key_type == 'DNS_R_TYPE' and val_type == 'SPF1'):
            print ("analyse_record2", "Explicit final",
                   'key_type', key_type,
                   'key', k,
                   'val_type', val_type,
                   'value', val,
                   file=sys.stderr)
            return

        elif key_type == 'FQDN' and val_type == 'NS':
            # The NS value is an FQDN per default
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val)
            return

        elif key_type == 'FQDN' and val_type == 'CNAME':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            d = str(val)[:-1]
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val)

        elif key_type == 'FQDN' and val_type == 'MX':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            priority = val.split()[0]
            exchange = val.split()[1][:-1]
            if w.count_fqdns_by_fqdn(exchange) == 0:
                w.add_fqdn(exchange)

        elif key_type == 'SPF1' and val_type == "INCLUDE":
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 'val_type', val_type, 'value', val, file=sys.stderr)
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val)

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
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k, 
                   'val_type', val_type, 'value', val, file=sys.stderr)

            # Currenct RR is uuid_child, which has an A result.
            # This is stored already. Need to add the IP
            # and bind the IP uuid to the RR uuid, which is the child_uuid 
            if w.count_ip_by_ip(val) == 0:
                if val_type == 'A':
                    uuid_ip = w.add_ip(val, 4)
                elif val_type == 'AAAA':
                    uuid_ip = w.add_ip(val, 6)

                    # The new IP needs an ASN resolve and IP to ASN attachment
                    # Take A or AAAA value to resolve as part of an AS plus AS info
                    asn_result = analyse_asn(val)

                    # The IP is now resolved to an ASN. Did we have this one from another ASN?
                    # If yes, get that one, if not, create a new one.
                    # Result is an uuid_asn
                    if w.count_asn_by_asn_and_asn_cidr(asn_result['asn'],
                                                       asn_result['asn_cidr']) == 0:
                        uuid_asn = w.add_asn(asn_result['asn'], asn_result['asn_description'],
                                             asn_result['asn_date'], asn_result['asn_registry'],
                                             asn_result['asn_country_code'], asn_result['asn_cidr'])
                    else:
                        rec_asn = w.get_asn_by_asn_and_asn_cidr(asn_result['asn'],
                                                                asn_result['asn_cidr'])
                        uuid_asn = rec_asn['uuid_asn']

                    # Combine this IP address with an the ASN per CIDR
                    w.add_ip2asn(uuid_ip, uuid_asn)

                    # TODO: ASN registration to AS number for linkage across CIDRs
            else:
                rec_ip = w.get_ip_by_ip(val)
                uuid_ip = rec_ip['ip']

            # in all cases, uuid_ip is the new one or the existing one
            w.add_dns_rr_to_ip(uuid_child, uuid_ip)

        else:
            print ("analyse_record2", "Final reached",
                   'key_type', key_type,
                   'key', k,
                   'val_type', val_type,
                   'value', val,
                   file=sys.stderr)

    except Exception as inst:
        print("analyse_record2", "Error:", type(inst), inst,
              'key_type', key_type, 'val_type', val_type, file=sys.stderr)


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
    if w.count_dns_rr_by_fqdn_and_r_type(fqdn, r_type) > 0:
        # The FQDN and Resource Type has been processed, no need to resolve it again.
        print("FQDN + Resource Type already resolved, skipping", fqdn, r_type, file=sys.stderr)
        return


    ### DNS Resolve FQDN with resource type
    answers = None
    q_dt = datetime.utcnow()
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
        resolver.nameservers=['127.0.0.1']
        resolver.timeout = 8
        resolver.lifetime = 8
        answers = resolver.query(fqdn, r_type)

        for r_data in answers:
            # Adding a DNS RR generates a new UUID, then link the parent to this.
            uuid_child = w.add_dns_rr(fqdn, r_type, str(r_data))
            w.add_dns_rr_parent_child(uuid_parent, uuid_child)

            # Let's go deeper with this RR
            analyse_record2(uuid_child, uuid_parent, fqdn, "FQDN", str(r_data), r_type, "RESOLVED", "", q_dt, "")

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
    results = []
    html = urlopen("https://certspotter.com/api/v0/certs?expired=false&duplicate=false&domain=" + base_fqdn)
    s = html.read()
    res = json.loads(s.decode('utf8'))

    for ct_cert in res:
        for fqdn in ct_cert['dns_names']:
            results.append(fqdn)
    return results


def resolve_multi_sub_domains(uuid_hunt, base_fqdn, s_dt):
    # Start concurrent worker threads
    if threaded:
        num_worker_threads = 50
        for i in range(num_worker_threads):
             t = threading.Thread(target=worker)
             t.daemon = True
             t.start()

    # Add the base
    #workload.append(base_fqdn)
    w.add_fqdn(base_fqdn)

    # Add static list
    temp = open(PATH + 'research.list','r').read().splitlines()
    for prefix in temp:
        w.add_fqdn(prefix + '.' + base_fqdn)

    # Use certificate transparency
    ct_res = add_ct_fqdn(uuid_hunt, base_fqdn, s_dt)
    for f in ct_res:
        w.add_fqdn(f)

    print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
    print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)

    # Total workload
    while True:
        l = w.get_fqdns_not_done()
        if len(l) == 0:
            print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
            print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)
            break

        for fqdn in l:
            print("FQDN to examine (workload)", fqdn, file=sys.stderr)
            #print(fqdn, file=sys.stderr)
            if threaded:
                q.put((uuid_hunt, fqdn, s_dt))
            else:
                resolve_multi_type(uuid_hunt, fqdn, s_dt)
                w.update_fqdns_status_by_fqdn(fqdn, "done")

        if threaded:
            q.join()       # block until all tasks are done

        print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
        print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)


##### MAIN #####
import argparse

# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'
warnings.filterwarnings('ignore')
threaded = False
if threaded:
    q = JoinableQueue()

# Parser
parser = argparse.ArgumentParser("domainhunter2.py")
parser.add_argument("--inject-uuid", help="UUID to inject as the primary key to this particular hunt.", type=str)
parser.add_argument('--debug', default=False, action="store_true", help="Print debug output")
parser.add_argument('--output', default=False, action="store_true", help="Draw output to this file")
parser.add_argument('domain', help="This domain will be hunted", type=str)
args = parser.parse_args()

# Generate or Get UUID for this hunt
if not args.inject_uuid:
    w = Workload(args.domain)
else:
    w = Workload(args.domain, args.inject_uuid)

print(str(w.uuid_hunt), "for a search on base FQDN", w.base_fqdn, "started at", str(w.s_dt), file=sys.stdout)

# Start the hunt
resolve_multi_sub_domains(w.uuid_hunt, w.base_fqdn, w.s_dt)

# Draw
if not args.output:
    w.draw(args.output)

##### MAIN #####


## Generic storage of this try.
## Create the database, incl tables
#create_db()
#store_hunt_domain(w.uuid_hunt, w.base_fqdn, w.s_dt)


