<?php
    require_once 'globals.php';

    /* Global initializers */
    if (!initialize()) {
        http_response_code(500);
        return;
    }


    #$DOMAINHUNTER_PY="./daemon_wrapper.sh python3 ./domainhunter2.py";
    $DOMAINHUNTER_PY="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ./domainhunter2.py";
    $PROCESS_POST_PHP="process_post.php";
    $extention = ".svg";


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

        /* Write sexy wrapper page */
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

        //open connection
        curl_setopt($ch,CURLOPT_POST,count($fields));
        curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);

        if ($scopecreep == "scopecreep") {
            $data = array("uuid_hunt" => $uuid, "domain" => $domain, "scopecreep" => 1);
        } else {
            $data = array("uuid_hunt" => $uuid, "domain" => $domain);
        }
        $data_string = json_encode($data);

        $ch = curl_init("http://localhost:5000/domainhunter");
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data_string))
        );
        $result = curl_exec($ch);
        print $result;

        /* header("refresh:1;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid); */
        header("refresh:1;url=index.html");


        return;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (! isset($_GET['uuid'])) {
            print "No uuid";
            header("refresh:4;url=index.html");
        } else {
            $uuid = $_GET['uuid'];

            print("results/" . $uuid . $extention);
            if (file_exists("results/" . $uuid . $extention)) {
                /* Redirect to end result */

                /* header("refresh:1;url=temp/" . $uuid . $extention); */
                header("refresh:1;url=results/" . $uuid . ".html");
            } else {
                print("<br>\nProcessing...\n");
                /* header("refresh:5;url=" . $PROCESS_POST_PHP . "?uuid=" . $uuid); */
                header("refresh:1;url=index.php");
            }
            return;
        }
    }
?>
