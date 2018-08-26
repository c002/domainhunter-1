#!/usr/bin/env python3

from kgraph import KGraph

import dns.resolver
from datetime import tzinfo, timedelta, datetime, timezone
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
import requests
import requests_cache
import json
from pygraphviz import *
import pprint



### Classes

class Workload:
    store_db = {}
    mem_db = {}

            # resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
    config_dns_resolvers = ['127.0.0.1']
    config_dns_timeout  = 8
    config_dns_lifetime = 8

    def __init__(self, base_fqdn, uuid_hunt=None):
        self.kg = KGraph()

        self.base_fqdn = base_fqdn
        self.wildcard_canary = 'wildcardcanary' + '.' + self.base_fqdn

        self.s_dt = datetime.timestamp(datetime.utcnow())
        if uuid_hunt is None:
            self.uuid_hunt = str(uuid.uuid4())
        else:
            self.uuid_hunt = uuid_hunt

        # Create first node
        m = {}
        m['uuid_hunt'] = self.uuid_hunt
        m['base_fqdn'] = self.base_fqdn
        m['s_dt'] = self.s_dt
        self.main_node_uuid = self.kg.store(m, 'DOMAINHUNT')

    def dns_resolve_r_type(self, fqdn, r_type):
        q_dt = datetime.utcnow()
        l = []
        try:
            resolver             = dns.resolver.Resolver()
            resolver.nameservers = self.config_dns_resolvers
            resolver.timeout     = self.config_dns_timeout
            resolver.lifetime    = self.config_dns_lifetime
            # DNS Resolve FQDN with specific resource type
            answers              = resolver.query(fqdn, r_type)

            for r_data in answers:
                rd = {}
                rd['fqdn'] = fqdn
                rd['r_type'] = r_type
                rd['r_data'] = str(r_data)
                rd['r_data_cleaned'] = re.sub(r'^"|"$|\.$', '', str(r_data))
                if r_type == 'MX':
                    rd['r_data_mx_priority'] = str(r_data).split()[0]
                    rd['r_data_mx_exchange'] = str(r_data).split()[1]
                    rd['r_data_mx_exchange_cleaned'] = str(r_data).split()[1][:-1]
                elif r_type == 'CAA':
                    options_caa = ['issue', 'issuewild', 'iodef']
                    if str(r_data).split()[1].lower() in options_caa:
                        rd['r_data_caa_tag'] = str(r_data).split()[0]
                        if str(r_data).split()[1].lower() == 'iodef':
                            rd['r_data_caa_iodef']         = str(r_data).split()[2]
                            rd['r_data_caa_iodef_cleaned'] = re.sub(r'^"|"$|\.$', '', 
                                                                    rd['r_data_caa_iodef'])
                        else:
                            rd['r_data_caa_issue_eec_kind'] = str(r_data).split()[1]
                            rd['r_data_caa_ca']         = str(r_data).split()[2]
                            rd['r_data_caa_ca_cleaned'] = re.sub(r'^"|"$|\.$', '',
                                                                 rd['r_data_caa_ca'])
#                elif r_type == 'TXT':
#                    if rd['r_data_cleaned'].lower().startswith('v=spf1'):

                l.append(rd)

            return l

        except dns.resolver.NXDOMAIN:
            print("Resolver warning: NXDOMAIN.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.resolver.NoAnswer:
            print("Resolver warning: SERVFAIL.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.exception.Timeout:
            print("Resolver error: Time out reached.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        except EOFError:
            print("Resolver error: EOF Error.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        except Exception as e:
            print("Resolver error:", e, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        return None

    def dns_resolve_multi_type(self, uuid_parent, fqdn):
        # Type options: A, AAAA, CAA, RRSIG, CNAME, MX, TXT,
        #               PTR, NS, NAPTR, SOA, SRV, SSHFP, TLSA, ANY

        # CNAME first
        answers = self.dns_resolve_r_type(fqdn, 'CNAME')
        if answers is not None:
            for a in answers:
                u = self.kg.store(a, 'DNS_RR')
                self.kg.store_relation(uuid_parent, u, 'DNS_RESOLVE_R_TYPE')

        if fqdn == self.base_fqdn:
            answers = self.dns_resolve_r_type(fqdn, 'SOA')
            if answers is not None:
                for a in answers:
                    u = self.kg.store(a, 'DNS_RR')
                    self.kg.store_relation(uuid_parent, u, 'DNS_RESOLVE_R_TYPE')

        # The rest, without CNAME, nor SOA
        types = ['A', 'AAAA', 'CAA', 'RRSIG', 'MX', 'TXT',
                 'PTR', 'NS', 'NAPTR', 'SRV', 'SSHFP', 'TLSA']
        for t in types:
            answers = self.dns_resolve_r_type(fqdn, t)
            if answers is not None:
                for a in answers:
                    u = self.kg.store(a, 'DNS_RR')
                    self.kg.store_relation(uuid_parent, u, 'DNS_RESOLVE_R_TYPE')


    ### Disk cache of dns_rr records for speed up
    ### TODO: should get a (longer) TTL
    def add_cache_entry(self, fqdn, r_type, value, error):
        return
        sql = ' '.join(["INSERT INTO dns_rr_cache",
                                    "(fqdn, r_type, value, error)"
                             "VALUES (:fqdn, :r_type, :value, :error)"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type,
                                         "value":value,
                                         "error":error})
        return True

    def has_cache_hit(self, fqdn, r_type, error):
        return False
        sql = ' '.join(["SELECT count(*)"
                          "FROM dns_rr_cache",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type",
                           "AND error = :error"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type,
                                         "error":error})
        cnt = self.store_db['cursor'].fetchone()[0]
        return cnt > 0

    def get_cache_hit(self, fqdn, r_type):
        return None
        sql = ' '.join(["SELECT fqdn, r_type, value, error"
                          "FROM dns_rr_cache",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type})
        res = self.store_db['cursor'].fetchone()

        rec = {}
        rec['fqdn'] = res[0]
        rec['r_type'] = res[1]
        rec['value'] = res[2]
        rec['error'] = res[3]
        return rec

    ### Clean up stuff, milage may vary...
    def detect_none_base_fqdn_rr_wilds_for_cleanup(self):
        all_recs = self.get_dns_rr()
        base_fqdn_rr = self.get_dns_rr_by_fqdn(self.base_fqdn)

        for ar in all_recs:
            if ar['r_type'] in ['NS', 'MX', 'SOA', 'TXT']:
                for bfr in base_fqdn_rr:
                    if bfr['r_type'] == ar['r_type'] and bfr['value'] == ar['value']:
                        print(bfr['r_type'], "==", ar['r_type'], "and", bfr['value'], "==", ar['value'])

                        # Remove from all_recs (in the db)
                        self.delete_dns_rr_by_fqdn_and_r_type(ar['fqdn'], ar['r_type'])

    def detect_and_remove_dns_wildcard(self):
        canary_recs = self.get_dns_rr_by_fqdn(self.wildcard_canary)
        print("Canary rec count:", len(canary_recs), file=sys.stderr)
        all_recs = self.get_dns_rr()
        print("All rec count:", len(all_recs), file=sys.stderr)

        # Is the data of the canary_recs is found in the all_recs, than
        # remove that record from the all_recs, unless it's the base_fqdn and the wildcard_canary itself
        for ar in all_recs:
            for cr in canary_recs:
                if ar['value'] == cr['value'] and ar['r_type'] == cr['r_type']:
                    # Eligable for removal
                    if ar['fqdn'] == self.base_fqdn or ar['fqdn'] == self.wildcard_canary:
                        continue
                    else:
                        # Remove from all_recs (in the db)
                        self.delete_dns_rr_by_fqdn_and_r_type(ar['fqdn'], ar['r_type'])

    ### Table: dns_rr
    def delete_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        # Remove linkages
        all_recs = self.get_dns_rr()
        for r in all_recs:
            if r['fqdn'] == g_fqdn and r['r_type'] == g_r_type:
                self.delete_dns_rr_to_ip_by_uuid_rr(r['uuid_rr'])

        # Remove DNS RR
        sql = ' '.join(["DELETE FROM dns_rr",
                              "WHERE fqdn = :fqdn",
                                "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                     {"fqdn":g_fqdn,
                                      "r_type":g_r_type})
        return True

    def count_dns_rr_by_r_type_and_value(self, c_r_type, c_value):
        sql = ' '.join(["SELECT count(*)"
                          "FROM dns_rr",
                         "WHERE r_type = :r_type",
                           "AND value = :value"])
        self.mem_db['cursor'].execute(sql,
                                      {"r_type":c_r_type,
                                       "value":c_value})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

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

    def get_dns_rr_by_fqdn(self, g_fqdn):
        all_dns_rr = []
        sql = ' '.join(["SELECT uuid_rr, fqdn, r_type, value",
                          "FROM dns_rr",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn})
        for (uuid_rr, fqdn, r_type, value) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_rr'] = uuid_rr
            rec['fqdn'] = fqdn
            rec['r_type'] = r_type
            rec['value'] = value
            all_dns_rr.append(rec)
        return all_dns_rr

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

    def count_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        sql = ' '.join(["SELECT count(*)",
                          "FROM dns_rr",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn, "r_type":g_r_type})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    ### Table: dns_rr_to_ip
    def delete_dns_rr_to_ip_by_uuid_rr(self, g_uuid_rr):
        sql = ' '.join(["DELETE FROM dns_rr_to_ip",
                              "WHERE uuid_rr = :uuid_rr"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_rr":g_uuid_rr})
        return True


    def add_dns_rr_to_ip(self, uuid_rr, uuid_ip):
        sql = ' '.join(["INSERT INTO dns_rr_to_ip",
                                    "(uuid_rr, uuid_ip)"
                             "VALUES (:uuid_rr, :uuid_ip)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_rr":uuid_rr,
                                      "uuid_ip":uuid_ip})
        return True

    ### Table: dns_rr_parent_child
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

    ### Table: fqdns
    def add_fqdn(self, fqdn, relation):
        f = {}
        f['fqdn'] = fqdn
        u = self.kg.store(f, 'WORKLOAD_FQDN_TODO')

        self.kg.store_relation(self.main_node_uuid, u, relation)
        return

    def get_fqdns_not_done(self):
        return self.kg.enum_objects_list('WORKLOAD_FQDN_TODO')

    def get_fqdns_by_fqdn(self, g_fqdn):
        records = []
        sql = ' '.join(["SELECT uuid_fqdn, fqdn, status, uuid_parent",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn})
        for (uuid_fqdn, fqdn, status, uuid_parent) in self.mem_db['cursor']:
            rec = {}
            rec['uuid'] = uuid_fqdn
            rec['fqdn'] = fqdn
            rec['status'] = status
            rec['uuid_parent'] = uuid_parent
            records.append(rec)
        return records

    def update_fqdns_status_by_fqdn(self, u_fqdn):
        li = self.kg.search_objects(rich='yes', and_class_name='WORKLOAD_FQDN_TODO', and_value=u_fqdn)
        for i in li:
            u = i['uuid_obj']

        self.kg.update_object_class_name(u, 'WORKLOAD_FQDN_DONE')
        return True

    def count_fqdns_by_fqdn(self, c_fqdn):
        sql = ' '.join(["SELECT count(*)",
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

    ### Table: asn
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

    def get_asns(self):
        asns = []
        sql = ' '.join(["SELECT uuid_asn, asn, asn_description,",
                               "asn_date, asn_registry, asn_country_code,",
                               "asn_cidr",
                          "FROM asn"])
        self.mem_db['cursor'].execute(sql)
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
            asns.append(rec)
        return asns

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

    ### Table: ip
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

    def get_ips(self):
        all_ips = []
        sql = ' '.join(["SELECT uuid_ip, ip, version",
                          "FROM ip"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_ip, ip, version) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['ip'] = ip
            rec['version'] = version
            all_ips.append(rec)
        return all_ips

    ### Table: ip2asn
    def add_ip2asn(self, uuid_ip, uuid_asn):
        sql = ' '.join(["INSERT INTO ip2asn (uuid_ip, uuid_asn)",
                                    "VALUES (:uuid_ip, :uuid_asn)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_ip":uuid_ip, "uuid_asn":uuid_asn})
        return True

    def get_ip2asns(self):
        all_ip2asns = []
        sql = ' '.join(["SELECT uuid_ip, uuid_asn",
                          "FROM ip2asn"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_ip, uuid_asn) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['uuid_asn'] = uuid_asn
            all_ip2asns.append(rec)
        return all_ip2asns

    ### Table: redirect
    def add_redirect(self, schema, fqdn, location):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO redirect (uuid_redir, schema, fqdn, location)",
                                    "VALUES (:uuid_redir, :schema, :fqdn, :location)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_redir":u,
                                       "schema":schema,
                                       "fqdn":fqdn,
                                       "location":location})
        return u

    def get_redirects(self):
        all_redirects = []
        sql = ' '.join(["SELECT uuid_redir, schema, fqdn, location",
                          "FROM redirect"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_redir, schema, fqdn, location) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_redir'] = uuid_redir
            rec['schema'] = schema
            rec['fqdn'] = fqdn
            rec['location'] = location
            all_redirects.append(rec)
        return all_redirects

    ### Table: fqdn2redirect
    def add_fqdn2redirect(self, uuid_fqdn, uuid_redir):
        sql = ' '.join(["INSERT INTO fqdn2redirect (uuid_fqdn, uuid_redir)",
                                    "VALUES (:uuid_fqdn, :uuid_redir)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_fqdn":uuid_fqdn,
                                       "uuid_redir":uuid_redir})
        return True

    def get_fqdn2redirects(self):
        all_fqdn2redirects = []
        sql = ' '.join(["SELECT uuid_fqdn, uuid_redir",
                          "FROM fqdn2redirect"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_fqdn, uuid_redir) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_fqdn'] = uuid_fqdn
            rec['uuid_redir'] = uuid_redir 
            all_fqdn2redirects.append(rec)
        return all_fqdn2redirects

    ### Drawing stuff
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

        # Cluster the Name Servers per domain and link them to the virtual blob
        ll_ns = {}
        for rec_ns in all_dns_rr:
            # Color by RR type
            if rec_ns['r_type'] == "NS":
                for rec_ns_inner in all_dns_rr:
                    if rec_ns_inner['r_type'] == "NS" and rec_ns['fqdn'] == rec_ns_inner['fqdn']:
                        if not rec_ns['fqdn'] in ll_ns:
                            ll_ns[rec_ns['fqdn']] = []

                        if rec_ns_inner['value'] not in ll_ns[rec_ns['fqdn']]:
                            ll_ns[rec_ns['fqdn']].append(rec_ns_inner['value'])

        for k in ll_ns.keys():
            ll_label = '\n'.join(sorted(ll_ns[k]))
            ll_label_start = ' '.join(['NS:', k, "\n"])

            u = str(uuid.uuid4())
            self.MainGraph.add_node(u, style='filled',
                                       color='gray30',
                                       fillcolor='cornsilk',
                                       fontcolor='black',
                                       label=ll_label_start + ll_label)

            for l_v in sorted(ll_ns[k]):
                for rec_ns in all_dns_rr:
                    if rec_ns['r_type'] == "NS" and rec_ns['fqdn'] == k and rec_ns['value'] == l_v:
                        self.MainGraph.add_edge(rec_ns['uuid_rr'], u)


        # HACK: re-plot the CNAME linkage to all RR types not yet linked
        for rr in self.get_dns_rr():
            if rr['r_type'] == 'CNAME':
                for rr_inner in self.get_dns_rr():
                    # Combine the CNAME value (minus the dot final character) to whatever RR
                    if rr['value'][:-1] == rr_inner['fqdn']:
                        self.add_dns_rr_parent_child(rr['uuid_rr'], rr_inner['uuid_rr'])

        # Plot the DNS RR Type linkages
        all_dns_rr_parent_child = self.get_dns_rr_parent_child()
        for rec in all_dns_rr_parent_child:
            # Link up node
            self.MainGraph.add_edge(rec['uuid_parent'], rec['uuid_child'])

        # Plot all IP addresses
        all_ips = self.get_ips()
        for rec in all_ips:
            # Plot all the nodes
            if rec['version'] == "6":
                self.MainGraph.add_node(rec['uuid_ip'], style='filled',
                                                        color='hotpink',
                                                        fontcolor='black',
                                        label=rec['ip'] + "\n" + "version: " + rec['version'])
            elif rec['version'] == "4":
                self.MainGraph.add_node(rec['uuid_ip'], style='filled',
                                                        color='lightpink1',
                                                        fontcolor='black',
                                        label=rec['ip'] + "\n" + "version: " + rec['version'])

        # Attach the IP addresses to the DNS RR records with these values
        for rec_rr in all_dns_rr:
            for rec_ip in all_ips:
                if rec_rr['value'] == rec_ip['ip']:
                    self.MainGraph.add_edge(rec_rr['uuid_rr'], rec_ip['uuid_ip'])

        # Plot AS Number info
        main_asn = []
        all_asns = self.get_asns()
        for rec in all_asns:
            ll = []
            ll.append("AS per CIDR\n")
            if rec['asn'] is not None:
                ll.append(rec['asn'])
                ll.append("\n")
            if rec['asn_description'] is not None:
                ll.append(rec['asn_description'])
                ll.append("\n")
            if rec['asn_date'] is not None:
                ll.append(rec['asn_date'])
                ll.append("\n")
            if rec['asn_cidr'] is not None:
                ll.append(rec['asn_cidr'])
                ll.append("\n")

            label = ' '.join(ll)
            self.MainGraph.add_node(rec['uuid_asn'], style='filled',
                                                     color='forestgreen',
                                                     fontcolor='white',
                                                     label=label)
            # Check if exists first, if not - add
            if not any(d.get('asn', None) == rec['asn'] for d in main_asn):
                m_asn = {}
                m_asn['uuid_main_asn'] = str(uuid.uuid4())
                m_asn['asn'] = rec['asn']
                m_asn['asn_description'] = rec['asn_description']
                m_asn['asn_registry'] = rec['asn_registry']
                m_asn['asn_country_code'] = rec['asn_country_code']
                main_asn.append(m_asn)

        # Attach the AS Number blobs (per CIDR) to the IP address
        all_ip2asns = self.get_ip2asns()
        for rec in all_ip2asns:
            self.MainGraph.add_edge(rec['uuid_ip'], rec['uuid_asn'])

        # Bonus - stitch ASN record blobs per CIDR to eac other per ASN
        for ma in main_asn:
            cidrs = []
            for rec in all_asns:
                if rec['asn'] == ma['asn']:
                    if 'asn_cidr' in rec and rec['asn_cidr'] is not None:
                        cidrs.append(rec['asn_cidr'])

            llma = []
            llma.append("ASN:\n")
            if ma['asn'] is not None:
                llma.append(ma['asn'])
                llma.append("\n")
            if ma['asn_description'] is not None:
                llma.append(ma['asn_description'])
                llma.append("\n")
            if ma['asn_registry'] is not None:
                llma.append(ma['asn_registry'])
                llma.append("\n")
            if ma['asn_country_code'] is not None:
                llma.append(ma['asn_country_code'])
                llma.append("\n")

            label = ' '.join(llma)

            for cidr in sorted(cidrs):
                label = label + "\n" + cidr

            self.MainGraph.add_node(ma['uuid_main_asn'], style='filled',
                                                         color='lawngreen',
                                                         fontcolor='black',
                                                         label=label)
        # Consolidate the ASN numbers by their number
        for rec in all_asns:
            for ma in main_asn:
                if rec['asn'] == ma['asn']:
                    self.MainGraph.add_edge(rec['uuid_asn'], ma['uuid_main_asn'])

        # URL location
        redir = self.get_redirects()
        for rd in redir:
            label = ''.join([rd['schema'],
                             rd['fqdn'], '\n',
                             'Location', '\n',
                             rd['location']
                             ])
            self.MainGraph.add_node(rd['uuid_redir'], style='filled',
                                                      color='purple',
                                                      fontcolor='white',
                                                      label=label)

            links = self.get_dns_rr_by_fqdn(rd['fqdn'])
            for l in links:
                self.MainGraph.add_edge(l['uuid_rr'], rd['uuid_redir'])
        # URL link fqdn to link
#        fqdn2redirects = self.get_fqdn2redirects()
#        for fr in fqdn2redirects:
#            self.MainGraph.add_edge(fr['uuid_fqdn'], fr['uuid_redir'])

    def draw_svg(self, destination):
        # Init graphviz
        self.MainGraph = AGraph(overlap=False,rankdir="LR")

        # Plot the map
        self.plot()

        # Finish lay-out and write the graph
        self.MainGraph.layout()
        self.MainGraph.draw(destination, prog='dot')

    def draw_txt(self, destination):
        f = open(destination, "w")
        all_dns_rr = self.get_dns_rr()
        all_dns_rr_parent_child = self.get_dns_rr_parent_child()
        for rec in all_dns_rr:
            for rec_pc in all_dns_rr_parent_child:
                if rec_pc['uuid_parent'] == self.uuid_hunt and rec['uuid_rr'] == rec_pc['uuid_child']:
                    f.write(''.join([self.base_fqdn, " (base2fqdn) ", rec['fqdn'], " {", rec['r_type'], "/", rec['value'], "}", "\n"]))

        for rec in all_dns_rr:
            f.write(''.join([rec['fqdn'], " (", rec['r_type'], ") ", rec['value'], "\n"]))

        # IP to ASN
        all_ips = self.get_ips()
        all_ip2asns = self.get_ip2asns()
        all_asns = self.get_asns()
        for rec in all_asns:
            llma = []
            llma.append("ASN:")
            if rec['asn'] is not None:
                llma.append(rec['asn'])
            if rec['asn_description'] is not None:
                llma.append(rec['asn_description'])
            if rec['asn_registry'] is not None:
                llma.append(rec['asn_registry'])
            if rec['asn_country_code'] is not None:
                llma.append(rec['asn_country_code'])
            label = ' '.join(llma)

            for rec_ip in all_ips:
                for ip2asn in all_ip2asns:
                    if ip2asn['uuid_ip'] == rec_ip['uuid_ip']:
                        if ip2asn['uuid_asn'] == rec['uuid_asn']:
                            f.write(''.join([rec_ip['ip'], " (ip2asn) ", label, "\n"]))

        f.close()


        # HACK: re-plot the CNAME linkage to all RR types not yet linked
#        for rr in self.get_dns_rr():
#            if rr['r_type'] == 'CNAME':
#                for rr_inner in self.get_dns_rr():
#                    # Combine the CNAME value to whatever RR
#                    if rr['value'] == rr_inner['fqdn']:
#                        self.add_dns_rr_parent_child(rr['uuid_rr'], rr_inner['uuid_rr'])


### Functions

def analyse_record2(uuid_child, uuid_parent, k, key_type, val, val_type, status, reason, dt, last_key_is_fqdn):
    try:
        # Remember where we came from. Required for SPF1 and DMARC
        if key_type == 'FQDN':
            last_key_is_fqdn = k

        if val_type == 'FQDN':
            # Need to resolve this FQDN again, but with the current uuid_child as its parent
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val, 'DISCOVERED')

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
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                                file=sys.stderr)
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val, 'DISCOVERED')
            return

        elif key_type == 'FQDN' and val_type == 'CNAME':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                               file=sys.stderr)
            # Clean up the result by ditching the dot
            cleaned_up_val = str(val)[:-1]

            # Add to main resolve if it was never on the list.
            if w.count_fqdns_by_fqdn(cleaned_up_val) == 0:
                # Avoid endless loops - most often this is just True
                if cleaned_up_val != k:
                    w.add_fqdn(cleaned_up_val, 'DISCOVERED')

            # Add link to existing FQDNs
            # First search for other records with this FQDN. Link with this, CNAME is the parent
                                    #parent, child
            res = w.get_dns_rr_by_fqdn(cleaned_up_val)
            for rr in res:
                print("CNAME link to DNS RR", rr['r_type'], rr['fqdn'], file=sys.stderr)
                w.add_dns_rr_parent_child(uuid_child, rr['uuid_rr'])


        elif key_type == 'FQDN' and val_type == 'MX':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                               file=sys.stderr)
            priority = val.split()[0]
            exchange = val.split()[1][:-1]
            if w.count_fqdns_by_fqdn(exchange) == 0:
                w.add_fqdn(exchange, 'DISCOVERED')

        elif key_type == 'SPF1' and val_type == "INCLUDE":
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                               file=sys.stderr)
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val, 'DISCOVERED')

        elif val_type == 'TXT':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                               file=sys.stderr)
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
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                                               'val_type', val_type, 'value', val,
                                               file=sys.stderr)
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

    # {'asn': '15169', 'asn_date': '2008-09-30', 'asn_description': 'GOOGLE -
    # Google LLC, US', 'asn_cidr': '2404:6800:4003::/48', 'asn_registry':
    # 'apnic', 'asn_country_code': 'AU'}

    # {'asn': '15169', 'asn_date': '2007-03-13', 'asn_description': 'GOOGLE -
    # Google LLC, US', 'asn_cidr': '74.125.200.0/24', 'asn_registry': 'arin',
    # 'asn_country_code': 'US'}


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


def req_get_inner(schema, fqdn_rec):
#    expire_after = timedelta(minutes=15)
#    requests_cache.install_cache('demo_cache1', expire_after=expire_after)

    base_url = schema + fqdn_rec['fqdn']
    try:
        r = requests.get(base_url, allow_redirects=False, timeout=2)
        if r.status_code >= 300 and r.status_code < 400:
            if 'Location' in r.headers.keys():
                u = w.add_redirect(schema, fqdn_rec['fqdn'], r.headers['Location'])
                w.add_fqdn2redirect(fqdn_rec['uuid'], u)
                print("Location found:",
                      schema + fqdn_rec['fqdn'],
                      r.headers['Location'],
                      file=sys.stderr)
                return True
    except:
        pass

    return False


def req_get(fqdn_rec):
    print(fqdn_rec)
    req_get_inner('http://', fqdn_rec)
    req_get_inner('https://', fqdn_rec)


def resolve_r_type(uuid_parent, fqdn, r_type):
    print("==============")
    answers = w.dns_resolve_r_type(fqdn, r_type)
#    if w.has_cache_hit(fqdn, r_type, "NXDOMAIN"):
#        print("Negative cache hit", fqdn, r_type, "NXDOMAIN", file=sys.stderr)
#        return False
#    if w.has_cache_hit(fqdn, r_type, "SERVFAIL"):
#        print("Negative cache hit", fqdn, r_type, "SERVFAIL", file=sys.stderr)
#        return False
#
#    if w.count_dns_rr_by_fqdn_and_r_type(fqdn, r_type) > 0:
#        # The FQDN and Resource Type has been processed, no need to resolve it again.
#        print("FQDN + Resource Type already resolved, skipping", fqdn, r_type, file=sys.stderr)
#        return True

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
            # Cache
#            w.add_cache_entry(fqdn, r_type, str(r_data), "SUCCESS")

            # Do I already have this result elsewhere?
            # TODO: Idea ... instead of skipping, link this to the most significant DNS RR.
#            cnt = w.count_dns_rr_by_r_type_and_value(r_type, str(r_data))
#            if cnt > 0 and r_type in ['MX', 'SOA', 'TXT']:
#                # Skip the recording
#                continue

            # Adding a DNS RR generates a new UUID, then link the parent to this.
            uuid_child = w.add_dns_rr(fqdn, r_type, str(r_data))
            w.add_dns_rr_parent_child(uuid_parent, uuid_child)

            # Let's go deeper with this RR
            analyse_record2(uuid_child, uuid_parent, fqdn, "FQDN", str(r_data), r_type, "RESOLVED", "", q_dt, "")

        return True

    except dns.resolver.NXDOMAIN:
        print("Resolver warning: NXDOMAIN.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        # Cache
        w.add_cache_entry(fqdn, r_type, "", "NXDOMAIN")
        pass
    except dns.resolver.NoAnswer:
        print("Resolver warning: SERVFAIL.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        # Cache
        w.add_cache_entry(fqdn, r_type, "", "SERVFAIL")
        pass
    except dns.exception.Timeout:
        print("Resolver error: Time out reached.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        # Cache
        w.add_cache_entry(fqdn, r_type, "", "TIMEOUT")
    except EOFError:
        print("Resolver error: EOF Error.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

    except Exception as e:
        print("Resolver error:", e, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

    return False



def add_ct_fqdn(base_fqdn, scopecreep):
    results = []
    html = urlopen("https://certspotter.com/api/v0/certs?expired=false&duplicate=false&domain=" + base_fqdn)
    s = html.read()
    res = json.loads(s.decode('utf8'))

    for ct_cert in res:
        for fqdn in ct_cert['dns_names']:
            if not scopecreep and not fqdn.endswith("." + base_fqdn):
                # Skip, because we are avoiding scope creep
                continue

            results.append(fqdn)
    return results


def load_sub_domains(scopecreep, sideload):
    # Add the base
    w.add_fqdn(w.base_fqdn, 'FQDN_BASE')

    # Add the wildcard canary
    w.add_fqdn(w.wildcard_canary, 'FQDN_WILDCARD_CANARY')

    # Add side loaded list
    if sideload is not None:
        for f in sideload:
            w.add_fqdn(f, 'FQDN_SIDELOADED')

    # Add static list
    temp = open(PATH + 'research.list','r').read().splitlines()
    for prefix in temp:
        w.add_fqdn(prefix + '.' + w.base_fqdn, 'FQDN_STATIC_RESEARCH_LIST')

    # Use certificate transparency
    ct_res = add_ct_fqdn(w.base_fqdn, scopecreep)
    for f in ct_res:
        w.add_fqdn(f, 'FQDN_CERTIFICATE_TRANSPARENCY')

def resolve_multi_sub_domains():
    print("Count todo", w.kg.count_objects_list('WORKLOAD_FQDN_TODO'), file=sys.stderr)
    print("Count done", w.kg.count_objects_list('WORKLOAD_FQDN_DONE'), file=sys.stderr)

    # Total workload
    while True:
        # Get all work on todo
        l = w.get_fqdns_not_done()
        if len(l) == 0:
            print("Count todo", w.kg.count_objects_list('WORKLOAD_FQDN_TODO'), file=sys.stderr)
            print("Count done", w.kg.count_objects_list('WORKLOAD_FQDN_DONE'), file=sys.stderr)
            break

        for fqdn_rec in l:
            print("FQDN to examine (workload)", fqdn_rec['fqdn'], file=sys.stderr)

            # Start resolving.
            w.dns_resolve_multi_type(w.main_node_uuid, fqdn_rec['fqdn'])

            # Flag this FQDN as done.
            w.update_fqdns_status_by_fqdn(fqdn_rec['fqdn'])

#            # HTTP Get and record Location
#            req_get(fqdn_rec)

        print("Count todo", w.kg.count_objects_list('WORKLOAD_FQDN_TODO'), file=sys.stderr)
        print("Count done", w.kg.count_objects_list('WORKLOAD_FQDN_DONE'), file=sys.stderr)

        print("-------------------------------------------------------")
        pp = pprint.PrettyPrinter(indent=3)
        pp.pprint(w.kg.enum_objects_list_rich())
        print("*******************************************************")

    # Post processing
    # Debug
    print(w.get_redirects())

#    w.detect_and_remove_dns_wildcard()
#    w.detect_none_base_fqdn_rr_wilds_for_cleanup()



##### MAIN #####
import argparse


# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

# Parser
parser = argparse.ArgumentParser("domainhunter2.py")
parser.add_argument('--debug', default=False, action="store_true", help="Print debug output")
parser.add_argument("--inject-uuid", help="UUID to inject as the primary key to this particular hunt.", type=str)
parser.add_argument("--sideload", help="Load additional FQDNs, each on a separate line to extend the hunt.", type=str)
parser.add_argument('--output', default=False, help="Draw output to this file", type=str)
parser.add_argument('--scopecreep', default=False, action="store_true", help="The certificate transparency can add other related domains. Add flag to enable scope creep")
parser.add_argument('domain', help="This domain will be hunted", type=str)
args = parser.parse_args()

# Generate or Get UUID for this hunt
if not args.inject_uuid:
    w = Workload(args.domain)
else:
    w = Workload(args.domain, args.inject_uuid)

# Side load
sideloaded = None
if args.sideload:
    if not os.path.isfile(args.sideload):
        print("Error: file", args.sideload, "does not exist")
        sys.exit(1)
    print("Loading", args.sideload, file=sys.stderr)
    sideloaded = open(args.sideload, 'r').read().splitlines()
    print("Loading done, found", len(sideloaded), "lines of FQDN(s)", file=sys.stderr)


# Announce
if args.output:
    print(str(w.uuid_hunt), "for a search on base FQDN", w.base_fqdn, "started at", str(w.s_dt), "output will be written to", args.output, file=sys.stdout)
else:
    print(str(w.uuid_hunt), "for a search on base FQDN", w.base_fqdn, "started at", str(w.s_dt), file=sys.stdout)

# Start the hunt
load_sub_domains(args.scopecreep, sideloaded)
resolve_multi_sub_domains()

# Draw
if args.output:
    print("Draw mode: plotting to", args.output, file=sys.stderr)
    if args.output.endswith(".svg"):
        w.draw_svg(args.output)
    elif args.output.endswith(".txt"):
        w.draw_txt(args.output)


# End
