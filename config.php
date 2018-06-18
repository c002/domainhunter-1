<?php

class Database {
    public $dsn  = 'sqlite:/var/www/domainhunter2.koeroo.net/db/domainhunter2.db';
    /* public $dsn  = 'mysql:host=127.0.0.1;port=3306;dbname=domainhunter'; */
    public $user = 'domainhunter';
    public $pass = 'domainhunter42';
    public $debug = True;
    public $handle;
}

