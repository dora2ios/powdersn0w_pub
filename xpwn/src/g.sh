#!/bin/bash

rm taig83.tar
mkdir BUILD

curl -OL http://apt.saurik.com/cydia/debs/taiguntether83x_2.3_iphoneos-arm.deb
dpkg-deb -x taiguntether83x_2.3_iphoneos-arm.deb BUILD/
rm taiguntether83x_2.3_iphoneos-arm.deb

cd BUILD
rm -rf System
mkdir -p usr/libexec/

sudo ln -s /taig/taig usr/libexec/CrashHousekeeping
sudo chmod 755 taig/taig
sudo chown 0:0 taig/
sudo chown 0:0 taig/taig

touch .cydia_no_stash
sudo chown 0:0 .cydia_no_stash

tar -cvf ../taig83.tar .cydia_no_stash taig/ usr/libexec/CrashHousekeeping

cd ..
sudo rm -rf BUILD

