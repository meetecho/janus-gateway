#!/bin/ash

path_janus='/usr/local/etc/janus'
cfg_janus="$path_janus/janus.cfg"
cfg_transport="$path_janus/janus.transport.rabbitmq.cfg"

cp $cfg_janus "$cfg_janus.tmp"
cp $cfg_transport "$cfg_transport.tmp"

envsubst < "$cfg_janus.tmp" > $cfg_janus
envsubst < "$cfg_transport.tmp" > $cfg_transport

sleep 2

/usr/local/bin/janus
