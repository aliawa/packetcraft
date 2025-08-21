import sys
sys.path.append('/home/user1/aawais/packetcraft')

import replay_data
import pytest
import logging
import yaml
import time

root_dir = "/home/user1/aawais/packetcraft"

@pytest.fixture(scope='module', autouse=True)
def init_test():
    replay_data.setup_logging(logging.DEBUG)


@pytest.fixture
def flows():
    server_ip  ='192.168.200.2'
    server_port='5060'
    return { 
            's2c' : {
                'proto':'tcp',
                'src':server_ip,
                'sport':server_port
                },
            'c2s' : {
                'proto':'tcp',
                'src':'192.168.100.2',
                'sport':'15600',
                'dst':server_ip,
                'dport':server_port
                }
            }
                

@pytest.fixture
def route_f():
    route_dir  = "routing"
    route_file = 'fw10_73_L3_src.yaml'
    return f"{root_dir}/{route_dir}/{route_file}"


@pytest.fixture
def scenario():
    test_dir = "tcp_segmentation"
    scnfile  = "invite_segs_template_sendonly.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict['scenario']


@pytest.fixture
def sendorder(request, scenario):
    segs = []
    for i in request.param:
        segs.append({'send' : {'flow':'c2s', 'name':'seg'+str(i)}})
        segs.append({'delay': {'timeout':5}})

    for i in range(len(scenario)):
        if 'noop' in scenario[i]:
            scenario[i:i] = segs
    return scenario


@pytest.mark.parametrize("sendorder",[ [1,2,3,4,5]], indirect=True)
def test_tcp_sip1(flows, route_f, sendorder):
    replay_data.setup(flows, route_f, None, None, None)
    time.sleep(1)
    replay_data.run_scenario(sendorder)

@pytest.mark.parametrize("sendorder",[ [1,3,4,5,2]], indirect=True)
def test_tcp_sip2(flows, route_f, sendorder):
    replay_data.setup(flows, route_f, None, None, None)
    time.sleep(1)
    replay_data.run_scenario(sendorder)

@pytest.mark.parametrize("sendorder",[ [3,4,5,2,1]], indirect=True)
def test_tcp_sip3(flows, route_f, sendorder):
    replay_data.setup(flows, route_f, None, None, None)
    time.sleep(1)
    replay_data.run_scenario(sendorder)
