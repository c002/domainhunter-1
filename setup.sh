#!/bin/bash


apt install python3-dnspython python3-mysqldb python3-pygraphviz
mysql -uroot -p < create.sql
mkdir temp
chown www-data:www-data temp/
