#How to crack a zip file

`Fcrackzip -D -p /path/to/wrodlist abcd.zip`

#How to crack/dict attack a 7zip file -

#!/bin/bash
# 7zip-JTR Decrypt Script
#
# Clone of JTR Decrypt Scripts by synacl modified for 7zip
# - RAR-JTR Decrypt Script - https://synacl.wordpress.com/2012/02/10/using-john-the-ripper-to-crack-a-password-protected-rar-archive/
# - ZIP-JTR Decrypt Script - https://synacl.wordpress.com/2012/08/18/decrypting-a-zip-using-john-the-ripper/

echo "7zip-JTR Decrypt Script";
if [ $# -ne 2 ]
then
  echo "Usage $0 <7z file> <wordlist>";
  exit;
fi
7z l $1

echo "Generating wordlist..."
john --wordlist="$2" --rules --stdout | while read i
do
  echo -ne "\rTrying \"$i\" "
  7z x -p$i $1 -aoa >/dev/null
  STATUS=$?
  if [ $STATUS -eq 0 ]; then
    echo -e "\rArchive password is: \"$i\""
    break
  fi
done
