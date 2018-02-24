<?php

require_once 'globals.php';


echo '<html>';
echo '   <body>';
echo '      <form action = "/process_post.php" method = "POST">';
echo '         Domain: <input type = "text" name = "domain"> <br>';
echo '         <input type = "submit" value = "Submit">';
echo '      </form>';


/* Global initializers */
if (!initialize()) {
    http_response_code(500);
    return;
}


$db = $GLOBALS['db'];
$products = array();
$sql = 'SELECT fqdn, uuid, s_dt '.
       '  FROM domainhunts ';
$sth = $db->handle->prepare($sql);
if (! $sth->execute()) {
    return NULL;
}

$rs = db_cast_query_results($sth);

echo '<table border=1>';
foreach($rs as $row) {
    echo '<tr>';

    echo '<td>' . $row['fqdn'] . '</td>';
    echo '<td>' . '<a href="/temp/'.$row['uuid'].'.html">'.$row['uuid'].'</a>' . '</td>';
    echo '<td>' . $row['s_dt'] . '</td>';

    echo '</tr>';
}
return $products;

echo '</table>';

echo '   </body>';
echo '</html>';

?>
