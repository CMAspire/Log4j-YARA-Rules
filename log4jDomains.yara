rule logj4Domains {
    meta: 
        descritpion = "Simple YARA rule to detect known Log4j Domains"
        author = "CM"
    
    strings:
        $string1 = "nazi.uy"
        $string2 = "abrahackbugs.xyz"
        $string3 = "cuminside.club"
        $stringashex1 = {6e 61 7a 69 2e 75 79} //string1 as hex
        $stringashex2 = {61 62 72 61 68 61 63 6b 62 75 67 73 2e 78 79 7a} //string2 as hex
        $stringashex3 = {63 75 6d 69 6e 73 69 64 65 2e 63 6c 75 62 0a} //string3 as hex


    condition:
        any of them  
}
