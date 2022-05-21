rule log4jURLs {
    meta:
        description = "Simple YARA rule to detect known Log4j URLs"
        author = "CM"

    strings:
        $string1 = "http://92.242.40.21/kinsing"
        $string2 = "http://138.197.206.223/wp-content/themes/twentysixteen/dk86"
        $string3 = "http://103.104.73.155:8080/index"
        $string4 = "http://155.94.154.170/aaa"
        $string5 = "http://198.98.60.67/bins/x86"
        $string6 = "http://185.250.148.157:8005/index"
        $string7 = "http://93.189.42.8/kinsing"
        $string8 = "http://92.242.40.21/lh2.sh"
        $string9 = "http://download.c3pool.com/xmrig_setup/raw/master/setup_c3pool_miner.sh"
        $string10 = "http://45.137.155.55/kinsing2"
        $string11 = "http://45.137.155.55/kinsing"
        $string12 = "http://80.71.158.12/kinsing"
        $string13 = "http://80.71.158.44/kinsing"
        $string14 = "http://198.98.60.67/bins/arm"
        $string15 = "http://103.104.73.155:8080/acc"
        $string16 = "http://192.210.200.66:1234/.rsyslogd"
        $string17 = "http://192.210.200.66:1234/.inis"
        $string18 = "http://2.58.149.95/8UsA.sh"
        $string19 = "http://135.148.91.146/bins.sh"
        $string20 = "http://2.58.149.95/bins/jerusalem.arm5"
        $string21 = "http://2.56.56.117/bins/exlir.x86"
        $string22 = "http://2.58.149.206/reader"
        $string23 = "http://2.56.56.117/zato/Josho.sh4"
        $string24 = "http://2.58.149.95/bins/jerusalem.sh4"
        $string25 = "http://2.58.149.95/bins/jerusalem.mpsl"
        $string26 = "http://2.56.56.117/bins/exlir.mips"
        $string27 = "http://2.56.56.117/zato/Josho.mpsl"
        $string28 = "http://2.56.56.117/bins/exlir.arm6"
        $string29 = "http://80.71.158.12:5557/Basic/Command/Base64/KGN1cmwgLXMgODAuNzEuMTU4LjEyL2xoLnNofHx3Z2V0IC1xIC1PLSA4MC43MS4xNTguMTIvbGguc2gpfGJhc2g="

    condition:
        any of them
}
