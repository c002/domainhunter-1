#!/bin/bash


apt install python3-dnspython python3-mysqldb python3-pygraphviz python3-pip
pip3 install ipwhois

mysql -uroot -p < create.sql
mkdir temp
chown www-data:www-data temp/
