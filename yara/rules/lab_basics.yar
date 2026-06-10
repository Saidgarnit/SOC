rule EICAR_Test {
    meta:
        description = "EICAR antivirus test file"
        mitre = "T1027"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Base64_Blob {
    meta:
        description = "Large base64 blob — possible encoded payload"
        mitre = "T1027"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        $b64
}

rule Webshell_PHP_Generic {
    meta:
        description = "Generic PHP webshell indicators"
        mitre = "T1505.003"
    strings:
        $s1 = "eval(base64_decode" ascii nocase
        $s2 = "system($_" ascii nocase
        $s3 = "passthru($_" ascii nocase
        $s4 = "shell_exec($_" ascii nocase
    condition:
        any of them
}

rule Reverse_Shell_Indicators {
    meta:
        description = "Common reverse shell strings"
        mitre = "T1059"
    strings:
        $bash  = "bash -i >& /dev/tcp/" ascii
        $nc    = "nc -e /bin/sh" ascii
        $python = "import socket,subprocess,os" ascii
    condition:
        any of them
}
