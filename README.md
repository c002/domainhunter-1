* Domain Hunter
This web-tool will use a list of domains and extract as much as possible from the full range of DNS record types and plots the results in a dependency tree.

---

```
# ./domainhunter2.py --help
usage: domainhunter2.py [-h] [--debug] [--inject-uuid INJECT_UUID]
                        [--load LOAD] [--output OUTPUT] [--scopecreep]
                        domain

positional arguments:
  domain                This domain will be hunted

optional arguments:
  -h, --help            show this help message and exit
  --debug               Print debug output
  --inject-uuid INJECT_UUID
                        UUID to inject as the primary key to this particular
                        hunt.
  --load LOAD           Load additional FQDNs, each on a separate line to
                        extend the hunt.
  --output OUTPUT       Draw output to this file
  --scopecreep          The certificate transparency can add other related
                        domains. Add flag to enable scope creep

```
---

* Dependencies
1. python3
2. python3-dnspython
3. python3-pygraphviz
4. pip3
5. pip3 install --upgrade ipwhois
6. pip3 install falcon
