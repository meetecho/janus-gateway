#!/bin/sh

set -e

SCRIPT_FILE=$(readlink -m "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_FILE")
IMAGE_FLAVOURS="base js-modules http-w-openssl"

build_docker_images_usage ()
{
    cat << USAGE
$(basename "$0") <docker-repository/namespace>

Builds images from *.docker files in this directory: $SCRIPT_DIR
You must pass it the name of the repository/namespace which the generated images should reside in.
Image flavours to be generated:
 - $IMAGE_FLAVOURS
USAGE
}

build_docker_image ()
{
    if [ ! -f "$SCRIPT_DIR/$2.docker" ]
    then
        echo "No such file: '$SCRIPT_DIR/$2.docker', please check/fix the flavour named '$2'"
        exit 254
    fi
    if [ "$2" = "base" ]
    then
        docker build -t "$1:$2" -f "$SCRIPT_DIR/$2.docker" "$SCRIPT_DIR"
    else
        docker build -t "$1:$2" - < "$SCRIPT_DIR/$2.docker"
    fi
}

if [ -n "$1" ]
then
  for flavour in $IMAGE_FLAVOURS
  do
    build_docker_image "$1" "$flavour"
  done
else
    build_docker_images_usage
    exit 255
fi

