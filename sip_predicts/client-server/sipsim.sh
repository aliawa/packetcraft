TMP=$HOME/tmp

#DIR=$HOME/packetcraft
#ROUTES_Srvr=vm17_56_server.yaml
#ROUTES_Clnt=vm16_49_client.yaml
#requirement for vm-17-55 setup:
#   1/1 192.168.60.1/24
#   1/2 192.168.61.1/24


DIR=$HOME/aliawa/packetcraft
ROUTES_Srvr=ocean_ranch_server_src.yaml
ROUTES_Clnt=ocean_ranch_client_src.yaml

case $1 in
    invite_server)
        sudo python3 $DIR/replay_data.py -sr $DIR/routing/$ROUTES_Clnt -t $DIR/sip_predicts/client-server/invite_converted_server.yaml -l INFO
        ;;
    register_client)
        sudo python3 $DIR/replay_data.py -sr $DIR/routing/$ROUTES_Clnt -t $DIR/sip_predicts/client-server/register_client.yaml -l INFO
        ;;
    invite_client)
        [ -z "$2" ] && echo -e "Port is requried\n" && exit
        echo "s2c_src: 192.168.70.220" > $TMP/myparam.yaml
        echo "s2c_port: $2" >> $TMP/myparam.yaml
        sudo python3 $DIR/replay_data.py -sr $DIR/routing/$ROUTES_Srvr -t $DIR/sip_predicts/client-server/invite_converted_client.yaml -l INFO -p $TMP/myparam.yaml
        ;;
    register_server)
        sudo python3 $DIR/replay_data.py -sr $DIR/routing/$ROUTES_Srvr -t $DIR/sip_predicts/client-server/register_server.yaml -l INFO
        ;;
    *) echo
        echo "Usage:"
        echo "  invite_server"
        echo "  invite_client <port>"
        echo "  register_client"
        echo "  register_server"
        echo
        ;;
esac
