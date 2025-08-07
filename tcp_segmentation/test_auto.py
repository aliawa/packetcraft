import replay_data
import pytest
import logging
import yaml
import time



@pytest.fixture(scope='module')
def init_test():
    replay_data.setup_logging(logging.WARN)

root_dir = "/home/aawais/packetcraft"
routes   = 'vm16_49_vwire_src_qa.yaml'
test_dir = "tcp_segmentation"
rout_dir = "routing"
scnfile  = "invite_segs_oo_appid_sendonly.yaml"


rout_f = f"{root_dir}/{rout_dir}/{routes}"

@pytest.mark.runlist
def test_tcp_segs(init_test):
    scen_f = f"{root_dir}/{test_dir}/{scnfile}"
    with open(scen_f, 'r') as f:
        scen_dict = yaml.full_load(f)
    flows = scen_dict['flows']
    for port in range(3000, 50000):
        flows['c2s']['sport']=port
        replay_data.setup(flows, rout_f, replay_data.Routing.source, None, None, None)
        time.sleep(1)
        replay_data.run_scenario(scen_dict['scenario'])

