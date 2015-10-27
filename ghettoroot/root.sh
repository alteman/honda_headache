#!/bin/sh
sh -x build.cmd; adb push libs/armeabi/ghettoroot /data/local/tmp/ghettoroot && adb shell "cd /data/local/tmp; chmod 0755 ghettoroot; ./ghettoroot $@"
