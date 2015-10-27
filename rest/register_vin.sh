#!/bin/bash

SERVER=ivhs.os.ixonos.com
#SERVER=ivhsqa.os.ixonos.com
#SERVER=ivhsdev.os.ixonos.com

VIN=5J6RM4H59FL094981

#FIXME
#VIN=5J6RM4H59FL094992
#VIN=$RANDOM

curl -c cookies.txt -A honda_android_headunit-version2_0 -v -u kmUAS34KNMS:POiul23MhOI -d "apikey=hyJgx756&devices=User-Agent:honda_android_headunit-version2_0&termsAccepted=true&locale=en&uid=$VIN" https://$SERVER/honda/mobile/registeruid
