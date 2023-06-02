#!/bin/bash
SNAME=$1

python3 update_scenario.py -i rtsp_tests_old/$SNAME -o $HOME/tmp/$SNAME
awk -f post_process.awk $HOME/tmp/$SNAME > rtsp_tests/$SNAME

