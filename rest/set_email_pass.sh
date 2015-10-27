#!/bin/bash

#SERVER=ivhs.os.ixonos.com
SERVER=ivhsqa.os.ixonos.com
EMAIL=aa@bbb.com
PASS=Password-0

curl -b cookies.txt -A honda_android_headunit-version2_0 -v -d "email=$EMAIL&password=$PASS&passwordVerification=$PASS" https://$SERVER/honda/component/updateemail
