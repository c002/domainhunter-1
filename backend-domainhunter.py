#!/usr/bin/env python3

from datetime import tzinfo, timedelta, datetime
import subprocess, os, sys
import time
import json
import uuid
import falcon
import requests
import requests_cache
import dns.resolver
from wsgiref import simple_server

URL_TLDS = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'


def domainhunter_start(j_args):
    # Data in j_args is already sanitized

    print('Launching domainhunter', j_args)

    if j_args.get("sideload") == "yes":
        otherfqdns = j_args.get("otherfqdns")

        # Line ending fix
        of = otherfqdns.replace("\r\n", "\n")
        of = of + "\n"

        uuid_sideload = str(uuid.uuid4())
        path_sideload = PATH + "temp/" + uuid_sideload + ".sideload"
        f = open(path_sideload, "w")
        f.write(of)
        f.close()

    my_cmd = []
    my_cmd.append("./domainhunter2.py")

    if j_args.get("scopecreep") == "yes":
        my_cmd.append("--scopecreep")

    my_cmd.append("--inject-uuid")
    my_cmd.append(j_args.get("uuid_hunt"))

    if j_args.get("sideload") == "yes":
        my_cmd.append("--sideload")
        my_cmd.append(path_sideload)

    my_cmd.append("--output")
    my_cmd.append("results/" + j_args.get("uuid_hunt") + ".svg")
    my_cmd.append(j_args.get("domain"))

    print("Executing domainhunter:", my_cmd)

    my_env = os.environ.copy()
    my_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" + my_env["PATH"]
    os.chdir("/var/www/domainhunter.koeroo.net")
    subprocess.Popen(my_cmd, env=my_env, stderr=subprocess.DEVNULL)

    # Clean up temp file, if created
#    if j_args.get("sideload") == "yes":
#        os.remove(path_sideload)

    if j_args.get("wrapper") == "yes":
        my_cmd = []
        my_cmd.append("./create_html_result_page.py")
        my_cmd.append("--schema")
        my_cmd.append("https://")
        my_cmd.append("--fqdn")
        my_cmd.append("domainhunter.koeroo.net")
        my_cmd.append("--resultdir")
        my_cmd.append("results/")
        my_cmd.append("--uuidhunt")
        my_cmd.append(j_args.get("uuid_hunt"))
        my_cmd.append("--resultext")
        my_cmd.append("svg")

        print("Executing wrapper html:", my_cmd)

        my_env = os.environ.copy()
        my_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" + my_env["PATH"]
        os.chdir("/var/www/domainhunter.koeroo.net")
        subprocess.Popen(my_cmd, env=my_env)

    os._exit(0)

def daemonize(func_child, j_args):
    newpid = os.fork()
    if newpid == 0:
        # Child 1
        # New session id
        os.setsid()
        # Double fork
        newpid = os.fork()
        if newpid == 0:
            # Child 2
            func_child(j_args)
        else:
            # Parent 2
            pids = (os.getpid(), newpid)
        # Exit child 1
        os._exit(0)
    else:
        # Parent 1
        os.waitpid(newpid, 0)
        pids = (os.getpid(), newpid)

def check_fqdn_is_legit(fqdn):
    expire_after = timedelta(minutes=30)
    requests_cache.install_cache('requests_tld_cache', expire_after=expire_after)

    base_url = URL_TLDS
    try:
        r = requests.get(base_url, allow_redirects=True, timeout=10)
        if (r.status_code >= 400 and r.status_code <600):
            return False

        for line in r.iter_lines():
            lo = fqdn.lower()
            if lo.endswith("." + line.decode('utf8').lower()):
                return True

    except:
        pass

    return False


def resolve_r_type(fqdn, r_type):
    ### DNS Resolve FQDN with resource type
    answers = None
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
        resolver.nameservers=['127.0.0.1']
        resolver.timeout = 8
        resolver.lifetime = 8
        answers = resolver.query(fqdn, r_type)

        results = []

        for r_data in answers:
            tup = {}

            tup['fqdn'] = fqdn
            tup['r_type'] = r_type
            if str(r_data)[-1:] == '.':
                tup['value'] = str(r_data)[:-1]
            else:
                tup['value'] = str(r_data)

            results.append(tup)
        return results

    except dns.resolver.NXDOMAIN:
        #print("Resolver warning: NXDOMAIN.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        pass
    except dns.resolver.NoAnswer:
        #print("Resolver warning: SERVFAIL.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        pass
    except dns.exception.Timeout:
        #print("Resolver error: Time out reached.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        pass
    except EOFError:
        print("Resolver error: EOF Error.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

    except Exception as e:
        print("Resolver error:", e, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

    return None


class DomainHunterAPI:
    CHUNK_SIZE_BYTES = 4096

    def on_get(self, req, res):
        res.status = falcon.HTTP_200
        res.body = "Domainhunter is Ready"

    def on_post(self, req, res):
        big_chunk = bytes()
        while True:
            chunk = req.stream.read(self.CHUNK_SIZE_BYTES)
            if not chunk:
                break

            big_chunk = big_chunk + chunk

        if len(big_chunk) == 0:
            res.body = 'Error: no data provided'
            res.status = falcon.HTTP_400
            return

        # Decode UTF-8 bytes to Unicode, and convert single quotes
        # to double quotes to make it valid JSON
        my_json = big_chunk.decode('utf8').replace("'", '"')
        j = json.loads(my_json)

        if j.get("uuid_hunt") is None:
            res.body = 'Error: no uuid_hunt provided'
            res.status = falcon.HTTP_400
            return

        if j.get("domain") is None:
            res.body = 'Error: no domain provided'
            res.status = falcon.HTTP_400
            return

        if not check_fqdn_is_legit(j.get("domain")):
            res.body = 'Error: not a ccTLD, gTLD or other legit TLD found'
            res.status = falcon.HTTP_404
            return


class CAAHunterAPI:
    CHUNK_SIZE_BYTES = 4096

    def on_get(self, req, res):
        res.status = falcon.HTTP_200
        res.body = "CAA hunter is Ready"

    def on_post(self, req, res):
        big_chunk = bytes()
        while True:
            chunk = req.stream.read(self.CHUNK_SIZE_BYTES)
            if not chunk:
                break

            big_chunk = big_chunk + chunk

        if len(big_chunk) == 0:
            res.body = 'Error: no data provided'
            res.status = falcon.HTTP_400
            return

        # Decode UTF-8 bytes to Unicode, and convert single quotes
        # to double quotes to make it valid JSON
        my_json = big_chunk.decode('utf8').replace("'", '"')
        j = json.loads(my_json)

        if j.get("domain") is None:
            res.body = 'Error: no domain provided'
            res.status = falcon.HTTP_400
            return

        if not check_fqdn_is_legit(j.get("domain")):
            res.body = 'Error: not a ccTLD, gTLD or other legit TLD found'
            res.status = falcon.HTTP_404
            return

        dns_rr_caa = resolve_r_type(j.get("domain"), 'CAA')
        if dns_rr_caa is None:
            res.status = falcon.HTTP_404
        else:
            res.body = str(dns_rr_caa)
            res.status = falcon.HTTP_200

### Main
if __name__ == "__main__":
    import argparse

    # Init
    PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

    # Parser
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument("--port",
                        help="Listening port number (default is 5000).",
                        type=int)
    parser.add_argument("--host",
                        default=None,
                        help="Listening on IP-address (default is 127.0.0.1).",
                        type=str)
    args = parser.parse_args()


    # Start
    api = falcon.API()
    api.add_route('/domainhunter', DomainHunterAPI())
    print("Loaded route: '/domainhunter'")
    api.add_route('/caahunter', CAAHunterAPI())
    print("Loaded route: '/caahunter'")

    if args.host:
        host = args.host
    else:
        host = '127.0.0.1'

    if args.port:
        port = args.port
    else:
        port = 5000

    httpd = simple_server.make_server(host, port, api)
    print("Operating on", host, "port", port, "from current working dir", PATH)
    print("Locked and loaded for the hunt!")
    httpd.serve_forever()
