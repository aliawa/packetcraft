if [[ $1 == "-h" || $1 == "--help" || -z "$1" ]]; then
    python3 replay_data.py $* 
    echo 
    exit
fi
sudo python3 replay_data.py $*
