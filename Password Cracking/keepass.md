# Cracking passwords from Keepass (.kdbx)

1. Run `keepass2john example.kdbx > out.hashes`
2. `john out.hashes`

OR

1. Hashcat - `hashcat -m 13400 -a 0 out.hashes wordlist`
