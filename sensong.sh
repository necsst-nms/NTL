#!/bin/sh

make -j 8 && make modules -j 8 && make modules_install  && make install

