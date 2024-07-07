#!/bin/bash
# See https://stackoverflow.com/a/32237064

as -o payload.o $1
ld --oformat binary -o payload payload.o
echo >> payload
# hd payload
wc -c payload
