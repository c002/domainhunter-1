<?php
    require_once 'globals.php';

    echo '<html>';
    echo '   <body>';
    echo '      <form action = "/process_post.php" method = "POST">';
    echo '         Domain: <input type="text" name="domain" autocomplete="off"> <br>';
    echo '         Scope creep: <input type="checkbox" name="scopecreep" value="scopecreep"> <br>';
    echo '         <input type = "submit" value = "Submit">';
    echo '      </form>';


    /* Global initializers */
    if (!initialize()) {
        http_response_code(500);
        return;
    }


    $sql = '   SELECT fqdn, uuid_hunt, status'.
           '     FROM domainhunts';
    $rs = $GLOBALS['db']->query($sql);

    echo '<table border=1>';
    foreach($rs as $row) {
        echo '<tr>';

        echo '<td>' . $row['fqdn'] . '</td>';
        if (file_exists("results/".$row['uuid_hunt'].".svg")) {
            echo '<td>' . '<a href="results/'.$row['uuid_hunt'].'.html">'. "Results" .'</a>' . '</td>';
        } else {
            echo '<td>' . $row['status'] . '</td>';
        }

        echo '</tr>';
    }
    echo '</table>';

    echo '   </body>';
    echo '</html>';
?>
