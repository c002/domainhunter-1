<?php
    require_once 'globals.php';

    header("refresh:30;url=index.html");

    echo '<html>';
    echo '   <body>';
    echo '   <input type="button" value="Refresh Page" onClick="window.location.reload()">';
    echo '   <br>';
    echo '   <br>';

    echo '      <form action = "/process_post.php" method = "POST">';
    echo '         Domain: <input type="text" name="domain" autocomplete="off"> <br>';
    echo '         Scope creep: <input type="checkbox" name="scopecreep" value="yes"> <br>';
    echo '         (Optional) Additional FQDNs:<br><TEXTAREA NAME="otherfqdns" ROWS=10 COLS=20 ></TEXTAREA>';
    echo '         <br>';
    echo '         <input type = "submit" value = "Submit">';
    echo '      </form>';


    /* Global initializers */
    if (!initialize()) {
        http_response_code(500);
        return;
    }


    $sql = '   SELECT fqdn, uuid_hunt, scopecreep, sideload, status'.
           '     FROM domainhunts';
    $rs = $GLOBALS['db']->query($sql);

    echo '<table border=1>';
    echo '<tr>';
    echo '<td>FQDN</td>';
    echo '<td>Scope creep</td>';
    echo '<td>Side loading</td>';
    echo '<td>Status</td>';
    echo '</tr>';
    foreach($rs as $row) {
        echo '<tr>';

        echo '<td>' . $row['fqdn'] . '</td>';
        echo '<td>' . $row['scopecreep'] . '</td>';
        echo '<td>' . $row['sideload'] . '</td>';
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
