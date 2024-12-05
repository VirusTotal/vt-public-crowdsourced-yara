rule MSANlocker
{
    meta:
        author = "Deathrobotpunch1"
        description = "MSAN Locker YARA rule"

    strings:
        $hex_strings1 = {48 56 57 41 54 41 55 41 56 41 57 49}
        $hex_strings2 = {41 32 84 24 4c 20 40 00}
        $hex_strings3 = {4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 67 01 45 78 69 74 50 72 6F 63 65 73 73 00 42 02 47 65 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 56 61 72 69 61 62 6C 65 41 00 4C 06 6C 73 74 72 63 70 79}
    condition:
        any of them
}
