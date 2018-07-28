#!/bin/bash


apt install screen python3-dnspython python3-pygraphviz python3-pip
pip3 install --upgrade ipwhois falcon
pip3 install falcon

mkdir results
mkdir db
mkdir temp

chown www-data:www-data results
chown www-data:www-data db
chown www-data:www-data temp

screen ./backend-domainhunter.py
