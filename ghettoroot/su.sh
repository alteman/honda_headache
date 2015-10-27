#!/system/bin/sh

mount -o rw,remount /system
cat /data/local/tmp/su >/system/xbin/su
chmod 06755 /system/xbin/su

