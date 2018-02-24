<?php
require_once 'config.php';
require_once 'database.php';

// require_once 'session.php';

function initialize() {
    date_default_timezone_set('Etc/UTC');
//    $GLOBALS['site'] = new Site;
//    $GLOBALS['mail'] = new Mail;
    /* Database */

    $db = db_connect();
    if ($db && $db->handle === NULL) {
        http_response_code(500);
        return False;
    }
    $GLOBALS['db'] = $db;

//    /* Session management */
//    session_mngt();

    return True;
}
