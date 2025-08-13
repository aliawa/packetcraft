DIR=$(dirname $0)
PYTHON=~/workspace/packetcraft/py_venv/bin/python

if [[ $1 == "-h" || $1 == "--help" || -z "$1" ]]; then
    $PYTHON -E $DIR/replay_data.py --help
    echo 
    exit
fi
sudo $PYTHON $DIR/replay_data.py $*
