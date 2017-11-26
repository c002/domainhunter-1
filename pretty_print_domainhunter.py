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
import os

if not 'PATH' in os.environ:
    os.environ["PATH"] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

threads = []

from pygraphviz import *

A = AGraph(overlap=False,rankdir="LR")


def open_db():
    db_o = {}
    db_o['connection'] = MySQLdb.connect('localhost', 'domainhunter', 'domainhunter42', 'domainhunter');
    db_o['cursor'] = db_o['connection'].cursor()
    return db_o

def close_db(db_o):
    db_o['cursor'].close()
    db_o['connection'].close()


def read_record_uuid_parent(uuid_parent):
    #pool_sema.acquire()
    db_o = open_db()

    print("Read the records with parent UUID", uuid_parent, file=sys.stderr)
    try:

        #db_o['cursor'].execute("SELECT uuid, uuid_parent, fqdn, r_type, value, s_dt, q_dt, r_dt " +
        db_o['cursor'].execute("SELECT auto_id, uuid, uuid_parent, fqdn, r_type, value " +
                               "  FROM dns_records " +
                               " WHERE uuid_parent = '" + uuid_parent + "'")

    except (MySQLdb.Error, MySQLdb.Warning) as inst:
        print("read_record_uuid:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    try:
        for (auto_id, uuid, uuid_parent, fqdn, r_type, value) in db_o['cursor']:
            print(auto_id, uuid, uuid_parent, fqdn, r_type, value, file=sys.stderr)


            if uuid == uuid_parent:
                A.add_node(uuid_main, color='blue', label="Main search domain is:\n" + fqdn)
                continue
            else:
                A.add_node(uuid, color='red', label="FQDN: " + fqdn + "\n" + r_type + "\n" + value)
                A.add_edge(uuid_parent, uuid)

                # Recurse
                read_record_uuid_parent(uuid)


    except Exception as inst:
        print("read_record_uuid:", "Unknown type of error is:", type(inst), inst, file=sys.stderr)

    close_db(db_o)
    #pool_sema.release()


def main_child(uuid_main):
    read_record_uuid_parent(uuid_main)


### MAIN ###
if len(sys.argv) != 3:
    print("Please provide one UUID and an output file")
    sys.exit(1)

uuid_main = sys.argv[1]
filename = sys.argv[2]


maxconnections = 10
pool_sema = threading.BoundedSemaphore(value=maxconnections)

print("Constructing view for", uuid_main, file=sys.stdout)
main_child(uuid_main)


#p = Process(target=main_child, args=(uuid_main, base_fqdn, s_dt))
#p.start()

A.draw(filename, prog='dot')
#A.draw("domainhunter.dot",prog='dot')


