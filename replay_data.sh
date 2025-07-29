DIR=$(dirname $0)

if [[ $1 == "-h" || $1 == "--help" || -z "$1" ]]; then
    python3 $DIR/replay_data.py --help
    echo 
    exit
fi
sudo -E python3.8 $DIR/replay_data.py $*
