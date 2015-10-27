#!/bin/bash

pushd "$( dirname "$BASH_SOURCE" )" >/dev/null
_BASEDIR=$PWD
popd >/dev/null

export WORKDIR=$_BASEDIR/.work/
export THIRDPARTY=$_BASEDIR/_thirdparty/

test -f "$_BASEDIR/env-user.sh" && . "$_BASEDIR/env-user.sh"

test -z "$(which adb)" && {
    echo "Please set Android SDK platform-tools path in env-user.sh" 1>&2
    echo "See env-user.sh.sample for details" 1>&2
    exit 1
}

test -z "$(which ndk-build)" && {
    echo "Please set Android NDK path in env-user.sh" 1>&2
    echo "See env-user.sh.sample for details" 1>&2
    exit 1
}

