#!/bin/sh
set -e

echo_eval ()
{
    echo $@
    eval $@
}

echo "SANITY CHECK: image is: '$image'"
if [ -n "$image" ]
then
    echo "Number of cores available on the build host: $(nproc)"
    if echo -n "$image" | grep -q js-modules
    then
        # pre-empt invocation of npm install during subsequent build
        # as that will probably not work because the docker container will probably not have access to a NPM package repository/registry
        echo_eval cd npm && rm -rf node_modules
        echo_eval npm install
        echo_eval cd ..
    fi
    echo_eval mkdir -p dist
    echo_eval docker pull \"$image\"
    echo_eval docker run -t -v \"$(pwd):/janus/src\" -v \"$(pwd)/dist:/janus/dist\" \"$image\"
else
    echo "Image required!"
    exit 1
fi
