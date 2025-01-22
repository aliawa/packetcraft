DIR=$HOME/packetcraft
TMP=$HOME/tmp


case $1 in
    invite_server)
        sudo python3 $DIR/replay_data.py -r $DIR/routing/ocean_ranch.yaml -t $DIR/sip_predicts/client-server/invite_converted_server.yaml -l INFO
        ;;
    register_client)
        sudo python3 $DIR/replay_data.py -s -r $DIR/routing/ocean_ranch.yaml -t $DIR/sip_predicts/client-server/register_client.yaml -l INFO
        ;;
    invite_client)
        echo "s2c_src: 192.168.70.220" > $TMP/myparam.yaml
        echo "s2c_port: $1" >> $TMP/myparam.yaml
        sudo python3 $DIR/replay_data.py -r $DIR/routing/ocean_ranch.yaml -t $DIR/sip_predicts/client-server/invite_converted_client.yaml -l INFO -p $TMP/myparam.yaml
        ;;
    register_server)
        sudo python3 $DIR/replay_data.py -r $DIR/routing/ocean_ranch.yaml -s -t $DIR/sip_predicts/client-server/register_server.yaml -l INFO
        ;;
esac
