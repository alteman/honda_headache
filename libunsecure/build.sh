#!/bin/bash

BASEDIR="$( dirname "$0" )"

. "$BASEDIR/../env.sh"

ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk
"$BASEDIR/apk/apk.sh"
