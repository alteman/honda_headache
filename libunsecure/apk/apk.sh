#!/bin/bash

BASEDIR="$( dirname "$0" )"

. "$BASEDIR/../../env.sh"

TMPZIP="$WORKDIR/tmp.zip"

rm -f $TMPZIP
pushd "$BASEDIR" >/dev/null
zip $TMPZIP lib/armeabi/libsecure_access.so
popd >/dev/null
java -jar $THIRDPARTY/AndroidZipArbitrage.jar $THIRDPARTY/HondaAppCenter_A1.apk.orig $TMPZIP -o $WORKDIR/HondaAppCenter_A1_mod.apk
echo "Output: $WORKDIR/HondaAppCenter_A1_mod.apk"
