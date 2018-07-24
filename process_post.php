<?php
    require_once 'globals.php';

    /* Global initializers */
    if (!initialize()) {
        http_response_code(500);
        return;
    }


    #$DOMAINHUNTER_PY="./daemon_wrapper.sh python3 ./domainhunter2.py";
    $DOMAINHUNTER_PY="PATH=usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ./domainhunter2.py";
    $PROCESS_POST_PHP="process_post.php";

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        /* Start processing */
        $domain = trim($_POST["domain"]);
        if (array_key_exists("scopecreep", $_POST)) {
            $scopecreep = trim($_POST["scopecreep"]);
        } else {
            $scopecreep = "no";
        }


        /* Sanitizer */
        if(preg_match('/[^\.a-zA-Z\-0-9]/i', $domain)) {
            header("refresh:4;url=index.html");
            print("Not a valid FQAN. No special characters allowed.\n");
            print("You typed: ");
            print($domain);
            return;
        }

        /* Store domainhunt */
        $sql = 'INSERT INTO domainhunts (uuid_hunt, fqdn, status)'.
               '     VALUES (:uuid_hunt, :fqdn, :status)';

        $uuid = guidv4();

        $GLOBALS['db']->begintransaction();
        $statement = $GLOBALS['db']->prepare($sql);
        $statement->execute(array(
                            "uuid_hunt" => $uuid,
                            "fqdn" => $domain,
                            "status" => "processing"
                           ));
        $GLOBALS['db']->commit();

        /* Input is clean, start processing */
//        print ("Start processing... ");
//        print ($domain);
//        print ("<br>");
        /* $cmd = $DOMAINHUNTER_PY . " " . $domain . " 2>/dev/null"; */
        $cmd = $DOMAINHUNTER_PY;
        if ($scopecreep == "scopecreep") {
            $cmd = $cmd . " --scopecreep";
        }
        $cmd = $cmd ." --inject-uuid ".$uuid;
        $cmd = $cmd ." --output results/".$uuid.".svg ".$domain." 2>/tmp/".$domain.".log";

        print ("Going for: ");
        print ("<br>");
        print ($cmd);
        print ("<br>");
        $output = system($cmd);
        print($output);
        print ("<br>");


        header("refresh:6;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid);

        return;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (! isset($_GET['uuid'])) {
            print "No uuid";
            header("refresh:4;url=index.html");
        } else {
            $uuid = $_GET['uuid'];

            $extention = ".svg";

            print("results/" . $uuid . $extention);
            if (file_exists("results/" . $uuid . $extention)) {
                /* Redirect to end result */
                $html = '<html><body>' . "\n" .
                        '<button onclick="window.location.href=\'/index.php\'">Return</button>'."\n" .
                        '<br>'."\n" .
                        '<style>'.
                        '.fit { width: 400%; }'.
                        '</style>'.
                        '<embed src="https://'.$_SERVER['SERVER_NAME'].'/results/' . $uuid . $extention . '" type="image/svg+xml"></embed>' .
                        '</body></html>'."\n";

                        /* '<img class="fit" src="/temp/' . $uuid . $extention . ">'. "\n" . */
                file_put_contents("results/" . $uuid . ".html", $html);

                /* header("refresh:1;url=temp/" . $uuid . $extention); */
                header("refresh:1;url=results/" . $uuid . ".html");
            } else {
                print("Processing...\n");
                header("refresh:5;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid);
            }
            return;
        }
    }
?>
