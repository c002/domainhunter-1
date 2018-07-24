#!/bin/bash


apt install python3-dnspython python3-pygraphviz python3-pip
pip3 install ipwhois

mkdir results
mkdir db

chown www-data:www-data results
chown www-data:www-data db

