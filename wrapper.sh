#!/bin/bash

UUID=$(dbus-uuidgen)

DOMAIN=""

SCOPECREEP="no"
for i in "$@"; do
    case $i in
        --scopecreep)
            SCOPECREEP="yes"
            shift
            ;;
        *)
            if [ "$DOMAIN" = "" ]; then
                DOMAIN=$1
            else
                echo "Input arguments error at: $@"
                exit 1
            fi
            ;;
    esac
done

echo "Domainhunt started for $DOMAIN at $UUID"

echo "insert into domainhunts (uuid_hunt, fqdn, status, scopecreep, sideload) values (\"$UUID\", \"$DOMAIN\", \"processing\", \"$SCOPECREEP\", \"no\")" | sqlite3 db/domainhunter2.db

if [ $SCOPECREEP = "yes" ]; then
    ./domainhunter2.py --inject-uuid $UUID --output results/$UUID.svg $DOMAIN
else
    ./domainhunter2.py --inject-uuid $UUID --scopecreep --output results/$UUID.svg $DOMAIN
fi
./create_html_result_page.py -v --schema https:// --fqdn domainhunter.koeroo.net --resultdir results/ --uuidhunt $UUID --resultext svg

echo "Domainhunt finished for $DOMAIN at $UUID"
