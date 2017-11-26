<?php
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
        $cmd = "/var/www/node.koeroo.net/domainhunter.py " . $domain . " 2>/dev/null";
        print ("Going for: ");
        print ($cmd);
        $output = system($cmd);
        print($output);
        $myArray = explode(' ', $output);
        $uuid = $myArray[0];



        header("refresh:2;url=process_post.php?uuid=" . $uuid);

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

            if (file_exists("/var/www/node.koeroo.net/temp/" . $uuid . $extention)) {
                /* Redirect to end result */
                $html = '<html><body>' . "\n" .
                        '<button onclick="window.location.href=\'/index.html\'">Return</button>'."\n" .
                        '<br>'."\n" .
                        '<style>'.
                        '.fit { width: 400%; }'.
                        '</style>'.
                        '<embed src="/temp/' . $uuid . $extention . '" type="image/svg+xml"></embed>' .
                        '</body></html>'."\n";

                        /* '<img class="fit" src="/temp/' . $uuid . $extention . ">'. "\n" . */
                file_put_contents("/var/www/node.koeroo.net/temp/" . $uuid . ".html", $html);

                /* header("refresh:1;url=temp/" . $uuid . $extention); */
                header("refresh:1;url=temp/" . $uuid . ".html");
                unlink("/tmp/" . $uuid);
            } else {
                if (! file_exists("/tmp/" . $uuid)) {
                    touch("/tmp/" . $uuid);
                    $cmd = "/var/www/node.koeroo.net/pretty_print_domainhunter.py " . $uuid . " " .
                           "/var/www/node.koeroo.net/temp/" . $uuid . $extention .
                           " 2>>/var/www/node.koeroo.net/temp/".$uuid.".log" .
                           " >> /var/www/node.koeroo.net/temp/".$uuid.".log";
                    system($cmd);
                }
                header("refresh:2;url=process_post.php?uuid=" . $uuid);
            }
            return;
        }
    }
?>
