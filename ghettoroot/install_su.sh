#!/bin/bash

adb push libs/armeabi/ghettoroot /data/local/tmp
#adb push busybox-armv7l /data/local/tmp/
adb push su /data/local/tmp/
adb push su.sh /data/local/tmp/
adb shell /data/local/tmp/ghettoroot 2 0 0 4 7 /data/local/tmp/su.sh
