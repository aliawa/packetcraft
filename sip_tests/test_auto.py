import sys
import pytest
import logging
import yaml
import time

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
    flows_obj['s2c']['src']   = '100.100.16.53'
    flows_obj['s2c']['sport'] = '5060'
    flows_obj['c2s']['src']   = '192.168.16.53'
    flows_obj['c2s']['sport'] = '15600'
    return flows_obj


def run_test (_flow, _scen, _route):
    replay_data.setup(_flow, _route, None, None, None)
    time.sleep(1)
    replay_data.run_scenario(_scen)


# ----------------------------------------------
# 
#                  Test 1
# 
# ----------------------------------------------

@pytest.fixture
def scenario_1():
    test_dir = "sip_tests"
    scnfile  = "sip_call.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


def test_sip1(route_f, scenario_1):
    run_test(flows(scenario_1['flows']), scenario_1['scenario'], route_f)



# ----------------------------------------------
# 
#                  Test 2
# 
# ----------------------------------------------


@pytest.fixture
def scenario_2():
    test_dir = "sip_predicts"
    scnfile  = "sip_invite_converted.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


def test_sip2(route_f, scenario_2):
    run_test(flows(scenario_2['flows']), scenario_2['scenario'], route_f)


# ----------------------------------------------
# 
#                  Test 3
# 
# ----------------------------------------------

@pytest.fixture
def scenario_3():
    test_dir = "sip_tests"
    scnfile  = "sip_parent_child_test.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


def test_sip3(route_f, scenario_3):
    run_test(flows(scenario_3['flows']), scenario_3['scenario'], route_f)



# ----------------------------------------------
# 
#                  Test 4
# 
# ----------------------------------------------

@pytest.fixture
def scenario_4():
    test_dir = "sip_tests"
    scnfile  = "sip_register.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


def test_sip4(route_f, scenario_4):
    run_test(flows(scenario_4['flows']), scenario_4['scenario'], route_f)
    replay_data.save_recv()



# ----------------------------------------------
# 
#                  Test 5
# 
# ----------------------------------------------

@pytest.fixture
def scenario_5():
    test_dir = "sip_tests"
    scnfile  = "sip_invite.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict

def flows_5(flows_obj):
    with open('recv.yaml', 'r') as file:
        data = yaml.safe_load(file)
        flows_obj['c2s']['src']   = '100.100.16.53'
        flows_obj['c2s']['sport'] = '5060'
        flows_obj['s2c']['src']   = data['contact_ip']
        flows_obj['s2c']['sport'] = data['contact_port']
        return flows_obj

def test_sip5(route_f, scenario_5):
    run_test(flows_5(scenario_5['flows']), scenario_5['scenario'], route_f)



# ----------------------------------------------
# 
#                  Test 6
# 
# ----------------------------------------------

@pytest.fixture
def scenario_6():
    test_dir = "sip_tests"
    scnfile  = "sip_register.yaml"
    scnpath  = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


def test_sip6(route_f, scenario_5):
    run_test(flows(scenario_6['flows']), scenario_6['scenario'], route_f)
    replay_data.save_recv()


