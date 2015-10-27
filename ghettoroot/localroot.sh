#!/system/bin/sh
cp libs/armeabi/ghettoroot /data/local/tmp/; cp -r data/local/tmp/* /data/local/tmp/; cd /data/local/tmp; chmod 0777 ghettoroot; ./ghettoroot $@
