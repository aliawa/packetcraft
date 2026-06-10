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
    replay_data.setup_logging(logging.INFO)


@pytest.fixture
def route_f():
    route_dir  = "routing"
    route_file = 'fw_17_55_L3_src_qa.yaml'
    return f"{root_dir}/{route_dir}/{route_file}"


@pytest.fixture
def flows_default():
    client_ip = '192.168.16.53'
    server_ip = '100.100.16.53'
    client_rtp= random.randint(10000,20000)
    server_rtp= random.randint(10000,20000)
    client_port= random.randint(6000,8000)

    flows_yaml = f"""
      c2s:
        proto: 'tcp'
        src: {client_ip}
        dst: {server_ip}
        sport: {client_port}
        dport: 5060
      s2c:
        proto: 'tcp'
        src: {server_ip}
        sport: 5060
      c2s_rtp:
        src: {client_ip}
        sport: {client_rtp}
      s2c_rtp:
        src: {server_ip}
        sport: {server_rtp}
      c2s_rtcp:
        src: {client_ip}
        sport: {client_rtp+1}
      s2c_rtcp:
        src: {server_ip}
        sport: {server_rtp+1}
    """
    return yaml.safe_load(flows_yaml)



@pytest.fixture
def flows_dstnat(flows_default):
    flows_defaut['c2s']['dst'] = '100.100.1.1'
    return flows_default


def run_tests (_scen, _flow, _route):
    replay_data.setup(_flow, _route, None, None, None)
    time.sleep(1)
    for scn in _scen:
        replay_data.run_scenario(scn)
    replay_data.stop()


def open_scenario(test_dir, scnfile):
    scnpath  = f"{test_dir}/{scnfile}"
    with open(scnpath, 'r') as f:
        scen_dict = yaml.full_load(f)
        return scen_dict


# ----------------------------------------------
# 
#                  Test 1
# 
# ----------------------------------------------
@pytest.fixture
def flows_default():
    client_ip = '192.168.16.53'
    server_ip = '100.100.16.53'
    client_rtp= random.randint(10000,20000)
    server_rtp= random.randint(10000,20000)
    client_port= random.randint(6000,8000)

    flows_yaml = f"""
      c2s:
        proto: 'tcp'
        src: {client_ip}
        dst: {server_ip}
        sport: {client_port}
        dport: 5060
      s2c:
        proto: 'tcp'
        src: {server_ip}
        sport: 5060
      c2s_rtp:
        src: {client_ip}
        sport: {client_rtp}
      s2c_rtp:
        src: {server_ip}
        sport: {server_rtp}
      c2s_rtcp:
        src: {client_ip}
        sport: {client_rtp+1}
      s2c_rtcp:
        src: {server_ip}
        sport: {server_rtp+1}
    """
    return yaml.safe_load(flows_yaml)


@pytest.fixture
def register():
    test_dir = f"{root_dir}/siptcp_tests"
    scnfile  = "qa_phone_1091_register.yaml"
    return open_scenario(test_dir, scnfile)

@pytest.fixture
def call():
    test_dir = f"{root_dir}/siptcp_tests"
    scnfile  = "qa_phone 1091_call.yaml"
    return open_scenario(test_dir, scnfile)

def test_sip1(route_f, flows_default, register, call):
    run_tests([register['scenario'],call['scenario']], register['flows'], route_f)


