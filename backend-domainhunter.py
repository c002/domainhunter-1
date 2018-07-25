#!/usr/bin/env python3

import os
import sys
import time
import json
import falcon
from wsgiref import simple_server


def domainhunter_start(j_args):
    print('Launch domainhunter')
    print(j_args)
    time.sleep(20)
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
        res.body = json.dumps({ '1': 'foo'})
    def on_post(self, req, res):
        big_chunk = bytes()
        while True:
            chunk = req.stream.read(self.CHUNK_SIZE_BYTES)
            if not chunk:
                break

            big_chunk = big_chunk + chunk

        if len(big_chunk) == 0:
            res.status = falcon.HTTP_400
            return

        # Decode UTF-8 bytes to Unicode, and convert single quotes
        # to double quotes to make it valid JSON
        my_json = big_chunk.decode('utf8').replace("'", '"')

        j = json.loads(my_json)

        daemonize(domainhunter_start, j)
        res.status = falcon.HTTP_200


api = falcon.API()
api.add_route('/domainhunter', DomainHunterAPI())


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 5000
    httpd = simple_server.make_server(host, port, api)
    httpd.serve_forever()
