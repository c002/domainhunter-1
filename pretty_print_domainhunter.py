#!/usr/bin/env python3

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import uuid
import sys
import threading
import ipaddress
from multiprocessing import Process, Queue
import re
import os
import hashlib

import sqlite3

if not 'PATH' in os.environ:
    os.environ["PATH"] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

threads = []
asn_list = {}

from pygraphviz import *

PATH = os.path.dirname(os.path.realpath(__file__)) + '/'


def open_db():
    db_o = {}
    db_o['connection'] = sqlite3.connect(PATH + 'db/domainhunter2.db')
    db_o['cursor'] = db_o['connection'].cursor()

    return db_o

def close_db(db_o):
    db_o['cursor'].close()
    db_o['connection'].close()


def read_record_uuid_parent(CurrGraph, uuid_lookup):
    db_o = open_db()

    try:
        print("Read the records with UUID to lookup", uuid_lookup, file=sys.stderr)
        db_o['cursor'].execute("SELECT uuid_dns, uuid_parent, fqdn, r_type, res " +
                               "  FROM dns " +
                               " WHERE uuid_parent = ?",
                               (uuid_lookup,))

    except Exception as inst:
        print("read_record_uuid_parent:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_dns, uuid_parent, fqdn, r_type, res) in db_o['cursor']:
            print (uuid_dns, uuid_parent, fqdn, r_type, res)

            if r_type == "CAA":
                CurrGraph.add_node(uuid_dns, style='filled', color='yellow', bgcolor='yellow', fontcolor='black', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "NS":
                CurrGraph.add_node(uuid_dns, style='filled', color='darkgoldenrod1', fontcolor='blue', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "MX":
                CurrGraph.add_node(uuid_dns, style='filled', color='orange', fontcolor='blue', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "SOA":
                CurrGraph.add_node(uuid_dns, style='filled', color='black', fontcolor='white', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "A":
                CurrGraph.add_node(uuid_dns, style='filled', color='red', fontcolor='white', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "AAAA":
                CurrGraph.add_node(uuid_dns, style='filled', color='crimson', fontcolor='white', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "CNAME":
                CurrGraph.add_node(uuid_dns, style='filled', color='gray40', fontcolor='white', label="" + fqdn + "\n" + r_type + "\n" + res)
            elif r_type == "TXT":
                CurrGraph.add_node(uuid_dns, style='filled', color='darkviolet', fontcolor='white', label="" + fqdn + "\n" + r_type + "\n" + res)
            else:
                CurrGraph.add_node(uuid_dns, color='red', label="" + fqdn + "\n" + r_type + "\n" + res)

            # Link up node
            CurrGraph.add_edge(uuid_parent, uuid_dns)

            # Recurse
            #ChildSubGraph = CurrGraph.add_subgraph(rank='same')
            ChildSubGraph = CurrGraph.add_subgraph()
            read_record_uuid_parent(ChildSubGraph, uuid_dns)

    except Exception as inst:
        print("read_record_uuid:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)


def make_hunt_node(CurrGraph, uuid_hunt):
    db_o = open_db()

    print("Read the records with parent UUID", uuid_hunt, file=sys.stderr)
    try:
        db_o['cursor'].execute("SELECT uuid_hunt, fqdn, s_dt " +
                               "  FROM domainhunts " +
                               " WHERE uuid_hunt = ?",
                               (uuid_hunt,))
    except Exception as inst:
        print("make_hunt_node:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_main, fqdn, s_dt) in db_o['cursor']:
            print ("Domainhunt", uuid_hunt, fqdn, s_dt)

            CurrGraph.add_node(uuid_hunt, style='filled', color='blue', fontcolor='white', label="Main search domain is:\n" + fqdn)

            # Recurse
            read_record_uuid_parent(CurrGraph, uuid_hunt)

    except Exception as inst:
        print("make_hunt_node:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)


def read_asn_uuid(uuid_asn):
    db_o = open_db()

    print("Read the ASN records with parent UUID", uuid_asn, file=sys.stderr)
    try:
        db_o['cursor'].execute("SELECT uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr " +
                               "  FROM asn " +
                               " WHERE uuid_asn = ?",
                               (uuid_asn,))

    except Exception as inst:
        print("read_asn_uuid:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr) in db_o['cursor']:
            print (uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr)

            A.add_node(uuid_asn, style='filled', color='green', fontcolor='white', label="" +
                       asn + "\n" +
                       asn_description + "\n" +
                       asn_date+ "\n" +
                       asn_registry+ "\n" +
                       asn_country_code+ "\n" +
                       asn_cidr)


    except Exception as inst:
        print("read_asn_uuid:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)


def read_asn(ASN_SubGraph, uuid_asn_lookup):
    db_o = open_db()

    try:
        print("Read the ASN record with a specific UUID", uuid_asn_lookup, file=sys.stderr)
        db_o['cursor'].execute("SELECT uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr " +
                               "  FROM asn " +
                               " WHERE uuid_asn = ?",
                               (uuid_asn_lookup,))

    except Exception as inst:
        print("read_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr) in db_o['cursor']:
            print (uuid_asn, uuid_parent, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr)

#            A.add_node(uuid_asn, style='filled', color='green', fontcolor='white', label="" +
#                       asn + "\n" +
#                       asn_description + "\n" +
#                       asn_date+ "\n" +
#                       asn_registry+ "\n" +
#                       asn_country_code+ "\n" +
#                       asn_cidr)
            ASN_SubGraph.add_node(uuid_asn, style='filled', color='green', fontcolor='white', label="" +
                       asn + "\n" +
                       asn_description + "\n" +
                       asn_date+ "\n" +
                       asn_registry+ "\n" +
                       asn_country_code+ "\n" +
                       asn_cidr)


    except Exception as inst:
        print("read_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)

def read_dns_to_asn(CurrGraph, uuid_hunt):
    db_o = open_db()

    #ASN_SubGraph = CurrGraph.add_subgraph(rank='same')
    ASN_SubGraph = CurrGraph.add_subgraph()

    print("Read the ASN records with hunt UUID", uuid_hunt, file=sys.stderr)
    try:
        db_o['cursor'].execute("SELECT uuid_hunt, uuid_asn, uuid_dns " +
                               "  FROM dns_to_asn " +
                               " WHERE uuid_hunt = ?",
                               (uuid_hunt,))

    except Exception as inst:
        print("read_dns_to_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        # Create a new subgraph, make rank is same => A.add_subgraph(sameNodeHeight, rank="same")
        for (uuid_hunt, uuid_asn, uuid_dns) in db_o['cursor']:
            print (uuid_hunt, uuid_asn, uuid_dns)
            #A.add_edge(uuid_dns, uuid_asn)
            ASN_SubGraph.add_edge(uuid_dns, uuid_asn)

            # Fetch ASN
            read_asn(ASN_SubGraph, uuid_asn)

    except Exception as inst:
        print("read_dns_to_asn:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)

def plot_asn_stuff(MainGraph, uuid_hunt):
    read_dns_to_asn(MainGraph, uuid_hunt)


def main_child(MainGraph, uuid_hunt):
    make_hunt_node(MainGraph, uuid_hunt)
    plot_asn_stuff(MainGraph, uuid_hunt)



### MAIN ###
if len(sys.argv) != 3:
    print("Please provide one UUID and an output file")
    sys.exit(1)

uuid_hunt = sys.argv[1]
filename = sys.argv[2]

print("Constructing view for", uuid_hunt, file=sys.stdout)
MainGraph = AGraph(overlap=False,rankdir="LR")
main_child(MainGraph, uuid_hunt)
MainGraph.layout()
MainGraph.draw(filename, prog='dot')

