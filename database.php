<?php
function db_connect() {
    try {
        $db = new Database;
        $db->handle = new PDO($db->dsn, $db->user, $db->pass);
        if ($db->debug) {
            $db->handle->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        }
    } catch (Exception $e) {
        return NULL;
    }
    return $db;
}

function db_cast_query_results($sth) {
    $rs = $sth->fetchAll(PDO::FETCH_ASSOC); 
    $new_rs = array();
    foreach($rs as $row) {
        $new_row = array();
        for ($i = 0; $i < $sth->columnCount(); $i++) {
            $meta = $sth->getColumnMeta($i);
            /* Casting */
            if ($meta["native_type"] === 'LONG' or $meta["native_type"] === 'INT') {
                $new_row[$meta["name"]] = $row[$meta["name"]];
                settype($new_row[$meta["name"]], "integer");
            } else {
                $new_row[$meta["name"]] = $row[$meta["name"]];
            }
        }
        array_push($new_rs, $new_row);
    }
    return $new_rs;
}
?>
