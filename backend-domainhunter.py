#!/usr/bin/env python3

import subprocess, os, sys
import time
import json
import falcon
from wsgiref import simple_server


def domainhunter_start(j_args):
    # Data in j_args is already sanitized

    print('Launching domainhunter', j_args)

    my_cmd = []
    my_cmd.append("./domainhunter2.py")

    if j_args.get("scopecreep") == "yes":
        my_cmd.append("--scopecreep")

    my_cmd.append("--inject-uuid")
    my_cmd.append(j_args.get("uuid_hunt"))

    my_cmd.append("--output")
    my_cmd.append("results/" + j_args.get("uuid_hunt") + ".svg")
    my_cmd.append(j_args.get("domain"))

    print("Executing domainhunter:", my_cmd)

    my_env = os.environ.copy()
    my_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" + my_env["PATH"]
    os.chdir("/var/www/domainhunter.koeroo.net")
    subprocess.Popen(my_cmd, env=my_env, stderr=subprocess.DEVNULL)
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

        daemonize(domainhunter_start, j)
        res.status = falcon.HTTP_200


api = falcon.API()
api.add_route('/domainhunter', DomainHunterAPI())


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 5000
    httpd = simple_server.make_server(host, port, api)
    print("Locked and loaded for the hunt!")
    httpd.serve_forever()
