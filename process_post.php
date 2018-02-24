<?php
    $TOPDIR="/var/www/domainhunter.koeroo.net";

    $DOMAINHUNTER_PY=$TOPDIR."/"."domainhunter.py";
    $PRETTY_PRINT_PY=$TOPDIR."/"."pretty_print_domainhunter.py";
    $DOMAIN_TEMPDIR=$TOPDIR."/"."temp/";
    $PROCESS_POST_PHP="process_post.php";


    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        /* Start processing */
        $domain = trim($_POST["domain"]);

        if(preg_match('/[^\.a-zA-Z\-0-9]/i', $domain)) {
            header("refresh:4;url=index.html");
            print("Not a valid FQAN. No special characters allowed.\n");
            print("You typed: ");
            print($domain);
            return;
        }

        print ($domain);

        /* Input is clean, start processing */
        print ("Start processing...");
        $cmd = $DOMAINHUNTER_PY . " " . $domain . " 2>/dev/null";
        print ("Going for: ");
        print ($cmd);
        $output = system($cmd);
        print($output);
        $myArray = explode(' ', $output);
        $uuid = $myArray[0];



        header("refresh:2;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid);

        return;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (! isset($_GET['uuid'])) {
            print "No uuid";
            header("refresh:4;url=index.html");
        } else {
            $uuid = $_GET['uuid'];
            print $uuid;

            $extention = ".svg";

            if (file_exists($DOMAIN_TEMPDIR . $uuid . $extention)) {
                /* Redirect to end result */
                $html = '<html><body>' . "\n" .
                        '<button onclick="window.location.href=\'/index.php\'">Return</button>'."\n" .
                        '<br>'."\n" .
                        '<style>'.
                        '.fit { width: 400%; }'.
                        '</style>'.
                        '<embed src="/temp/' . $uuid . $extention . '" type="image/svg+xml"></embed>' .
                        '</body></html>'."\n";

                        /* '<img class="fit" src="/temp/' . $uuid . $extention . ">'. "\n" . */
                file_put_contents($DOMAIN_TEMPDIR . $uuid . ".html", $html);

                /* header("refresh:1;url=temp/" . $uuid . $extention); */
                header("refresh:1;url=temp/" . $uuid . ".html");
                unlink("/tmp/" . $uuid);
            } else {
                if (! file_exists("/tmp/" . $uuid)) {
                    touch("/tmp/" . $uuid);
                    $cmd = $PRETTY_PRINT_PY . " " . $uuid . " " .
                           $DOMAIN_TEMPDIR . $uuid . $extention .
                           " 2>>".$DOMAIN_TEMPDIR.$uuid.".log" .
                           " >> ".$DOMAIN_TEMPDIR.$uuid.".log";
                    system($cmd);
                }
                header("refresh:2;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid);
            }
            return;
        }
    }
?>
