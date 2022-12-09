cd /root
ls -al
bunzip2 tools.tar.bz2
tar xvf tools.tar
ls
./runwww.py 443
shred -uz tools/* tools.tar
rmdir tools
ls
exit
