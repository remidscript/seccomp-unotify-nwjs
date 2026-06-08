#!/usr/bin/env bash

rm libhook
rm error.log
output=$(gcc hook.c -o sechook -ldl 2>&1) || echo "$output" >> error.log
exit
