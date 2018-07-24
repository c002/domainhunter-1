<?php
    function db_connect() {
        return $db;
    }

    function initialize() {
        date_default_timezone_set('Etc/UTC');
        chdir($_SERVER["DOCUMENT_ROOT"]);

        /* Database */
        try {
            $db = new PDO('sqlite:db/domainhunter2.db');
            $GLOBALS['db'] = $db;
        } catch (Exception $e) {
            http_response_code(500);
            return False;
        }

        try {
            $GLOBALS['db']->begintransaction();
            $GLOBALS['db']->exec("CREATE TABLE IF NOT EXISTS domainhunts (uuid_hunt TEXT, fqdn TEXT, status TEXT)");
            $GLOBALS['db']->commit();
        } catch (Exception $e) {
            print($e);
        }

    //    /* Session management */
    //    session_mngt();

        return True;
    }

    function guidv4()
    {
        if (function_exists('com_create_guid') === true)
            return trim(com_create_guid(), '{}');

        $data = openssl_random_pseudo_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

?>
