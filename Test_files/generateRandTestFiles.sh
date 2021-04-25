#!/bin/bash


dd if=/dev/urandom of=./128MB_rand.txt bs=64M count=2
dd if=/dev/urandom of=./256MB_rand.txt bs=64M count=4
dd if=/dev/urandom of=./512MB_rand.txt bs=64M count=8
dd if=/dev/urandom of=./1GB_rand.txt bs=64M count=16

