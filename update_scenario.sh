#!/bin/bash

# converts the scenario 'SNAME' from OLD_SCN_DIR to NEW_SCN_DIR/SNAME
OLD_SCN_DIR=rtsp_tests_old
NEW_SCN_DIR=rtsp_tests
SNAME=$1

if [ "$#" -eq 0 ];then
    echo "Usage:"
    echo "  $(basename $0) <scenario-name>"
    echo
    exit
else
    echo "Updating: $SNAME"
fi


python3 update_scenario.py -i $OLD_SCN_DIR/$SNAME -o $HOME/tmp/$SNAME
awk -f post_process.awk $HOME/tmp/$SNAME > $NEW_SCN_DIR/$SNAME

