#!/bin/bash

echo "delete from dns_rr_cache;" | sqlite3 db/domainhunter2.db
echo "delete from domainhunts;" | sqlite3 db/domainhunter2.db
rm temp/*
rm results/*
