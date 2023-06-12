#!/bin/bash

DEFAULT_DIR=$HOME/packetcraft/rtsp_tests

if [[ $1 != *"/"* ]]; then 
    SCENARIO_FL=$DEFAULT_DIR/$1
else
    SCENARIO_FL=$1
fi

sudo python3 replay_data.py  -r rtsp_tests/routing_192_1.yaml -l INFO  -s -t $SCENARIO_FL

