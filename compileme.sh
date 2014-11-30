#! /bin/bash
sh autogen.sh
./configure --prefix=/opt/janus  --disable-rabbitmq
make 
sudo make install
sudo make configs