#!/usr/bin/env python3

import argparse
import os
import sys


# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

# Parser
parser = argparse.ArgumentParser("create_html_result_page.py")
parser.add_argument('-v', '--verbose', dest='verbose', default=False, action="store_true", help="Print more info")
parser.add_argument("--schema", help="http:// or https://", type=str, required=True)
parser.add_argument("--fqdn", help="FQDN or host component of an URL", type=str, required=True)
parser.add_argument("--resultdir", help="(relative) directory for the results", type=str, required=True)
parser.add_argument("--uuidhunt", help="UUID of the hunt", type=str, required=True)
parser.add_argument("--resultext", help="File extention of the resulting file, like svg", type=str, required=True)
args = parser.parse_args()


# Processing
if args.schema != 'http://' and args.schema != 'https://':
    print("Only http:// or https:// as schema allowed")
    sys.exit(1)


url = args.schema + args.fqdn + "/" + args.resultdir + args.uuidhunt + args.resultext

l_url = []
l_url.append(args.schema)
l_url.append(args.fqdn)
if args.resultdir[0] != '/':
    l_url.append("/")
l_url.append(args.resultdir)
if args.resultdir[-1:] != '/':
    l_url.append("/")
l_url.append(args.uuidhunt)
if args.resultext[0] != '.':
    l_url.append(".")
l_url.append(args.resultext)

url = ''.join(l_url)

html = ' '.join(['<html><body>\n',
                 '<button onclick="window.location.href=\'/index.php\'">Return</button>',
                 '<br>\n',
                 '<style>',
                 '.fit { width: 400%; }',
                 '</style>',
                 '<embed src="' + url + '"',
                 'type="image/svg+xml"></embed>',
                 '</body></html>\n'])

fpath = "./" + args.resultdir + "/" + args.uuidhunt + ".html"
f = open(fpath,'w')
f.write(html)

if args.verbose:
    print("URL:", url, "in file", fpath)

