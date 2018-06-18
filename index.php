<?php

require_once 'globals.php';


echo '<html>';
echo '   <body>';
echo '      <form action = "/process_post.php" method = "POST">';
echo '         Domain: <input type="text" name="domain" autocomplete="off"> <br>';
echo '         <input type = "submit" value = "Submit">';
echo '      </form>';


/* Global initializers */
if (!initialize()) {
    http_response_code(500);
    return;
}

$db = db_connect();
if ($db == NULL) {
    echo 'DB connection problem';
    return;
}

$products = array();
$sql = '   SELECT fqdn, uuid_hunt, s_dt '.
       '     FROM domainhunts'.
       ' ORDER BY s_dt';
$rs = $db->handle->query($sql);

echo '<table border=1>';
foreach($rs as $row) {
    echo '<tr>';

    echo '<td>' . $row['fqdn'] . '</td>';
    echo '<td>' . '<a href="/temp/'.$row['uuid_hunt'].'.html">' . $row['s_dt'] . '</a>' . '</td>';

    echo '</tr>';
}
return $products;

echo '</table>';

echo '   </body>';
echo '</html>';

?>
