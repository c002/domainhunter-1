UUID=$(dbus-uuidgen)

if [ -z $1 ]; then
    echo "Provide a domain"
    exit 1
fi
DOMAIN=$1

echo "Domainhunt started for $DOMAIN at $UUID"

echo "insert into domainhunts (uuid_hunt, fqdn, status) values (\"$UUID\", \"$DOMAIN\", \"processing\")" | sqlite3 db/domainhunter2.db
./domainhunter2.py --inject-uuid $UUID --output results/$UUID.svg $DOMAIN
./create_html_result_page.py --schema https:// --fqdn domainhunter.koeroo.net --resultdir results/ --uuidhunt $UUID --resultext svg

echo "Domainhunt finished for $DOMAIN at $UUID"


exit 0

# ./domainhunter2.py -h
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


