#!/bin/bash

VIN=5J6RM4H59FL094981

#PROD
SERVER=ivhs.os.ixonos.com
PASSKEY=e0b25074-0c7b-4f27-b184-58063e42e982
#QA
SERVER=ivhsqa.os.ixonos.com
#PASSKEY=4f62eeb4-bf01-4609-86c4-68dd0b456ff0
PASSKEY=b0a7e359-9623-4023-a022-154dde367df4
VIN=4122

#curl -A honda_android_headunit-version2_0 -v -u $VIN:$PASSKEY -d "uid=$VIN&passkey=$PASSKEY&action=idlogin&Accept=application/json" https://$SERVER/honda/session
#curl -c cookies.txt -A honda_android_headunit-version2_0 -v -d "uid=$VIN&passkey=$PASSKEY&action=idlogin&Accept=application/json" https://$SERVER/honda/session
#echo curl -c cookies.txt -A honda_android_headunit-version2_0 -v -u "$VIN:$PASSKEY" -d "uid=$VIN&passkey=$PASSKEY&action=idlogin&Accept=application/json" https://$SERVER/honda/session
#curl -c cookies.txt -A honda_android_headunit-version2_0 -v -u "$VIN:$PASSKEY" -d "uid=$VIN&passkey=$PASSKEY&action=idlogin&Accept=application/json" https://$SERVER/honda/session
curl -c cookies.txt -A honda_android_headunit-version2_0 -v -d "uid=$VIN&passkey=$PASSKEY&action=idlogin&Accept=application/json" https://$SERVER/honda/session
