import sys
import pytest
import logging
import yaml
import time
import random

root_dir = "/home/aawais/packetcraft"
sys.path.append(root_dir)
import replay_data

# ----------------------------------------------
# 
#                  common
# 
# ----------------------------------------------

@pytest.fixture(scope='module', autouse=True)
def init_test():
    replay_data.setup_logging(logging.DEBUG)


@pytest.fixture
def route_f():
    route_dir  = "routing"
    route_file = 'fw_17_55_L3_src.yaml'
    return f"{root_dir}/{route_dir}/{route_file}"


def flows(flows_obj):
    client_ip = '192.168.16.53'
    server_ip = '100.100.16.53'
    client_rtp= random.randint(10000,20000)
    server_rtp= random.randint(10000,20000)

    flows_obj['s2c']['src']        = server_ip
    flows_obj['s2c']['sport']      = 5060
    flows_obj['s2c']['proto']      = 'tcp'
    flows_obj['c2s']['src']        = client_ip
    flows_obj['c2s']['sport']      = random.randint(8000,9999) 
    flows_obj['c2s']['proto']      = 'tcp'

    flows_obj.update({'c2s_rtp' :{'src':client_ip, 'sport':client_rtp}})
    flows_obj.update({'s2c_rtp' :{'src':server_ip, 'sport':server_rtp}})
    flows_obj.update({'c2s_rtcp':{'src':client_ip, 'sport':client_rtp+1}})
    return flows_obj


def run_test (_scen, _flow_adaptor, _route):
    replay_data.setup(_flow_adaptor(_scen['flows']), _route, None, None, None)
    time.sleep(1)
    replay_data.run_scenario(_scen['scenario'])
    replay_data.stop()


def open_scenario(test_dir, scnfile, root=root_dir):
    scnpath  = f"{root}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


# ----------------------------------------------
# 
#                  Test 1
# 
# ----------------------------------------------

@pytest.fixture
def scenario_1():
    test_dir = "siptcp_tests"
    scnfile  = "invite_1.0.yaml"
    return open_scenario(test_dir, scnfile)

def test_sip1(route_f, scenario_1):
    run_test(scenario_1, flows, route_f)



# ----------------------------------------------
# 
#                  Test 2
# 
# ----------------------------------------------

@pytest.fixture
def scenario_2():
    test_dir ="siptcp_tests"
    scnfile = "invite_pan_318464.yaml"
    return open_scenario(test_dir, scnfile)


def test_sip2(route_f, scenario_1):
    run_test(scenario_1, flows, route_f)



# ----------------------------------------------
# 
#                  Test 3
# 
# ----------------------------------------------

@pytest.fixture
def scenario_3():
    test_dir = "siptcp_tests"
    scnfile  = "invite_5.1.yaml"
    return open_scenario(test_dir, scnfile)


def test_sip3(route_f, scenario_3):
    run_test(scenario_3, flows, route_f)


# ----------------------------------------------
# 
#                  Test 4
# 
# ----------------------------------------------

@pytest.fixture
def scenario_3():
    test_dir = "siptcp_tests"
    scnfile  = "sip_call.yaml"
    return open_scenario(test_dir, scnfile)


def test_sip3(route_f, scenario_3):
    run_test(scenario_3, flows, route_f)


