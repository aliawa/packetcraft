import replay_data
import pytest
import logging
import glob

root_dir = "/home/aawais/workspace/scapy/siptcp/"


@pytest.fixture(scope="module")
def scn_param_srcnat():
    return root_dir + "params.srcnat.yaml"

@pytest.fixture(scope="module")
def rout_192_0_nat():
    return root_dir + "routing_192_0_nat.yaml"

PARAMS = [
        "scn_invite_1.0.yaml",
        "scn_invite_2.0.yaml","scn_invite_2.1.yaml", 
        "scn_invite_3.1.yaml", "scn_invite_3.2.yaml",
        "scn_invite_3.3.yaml", "scn_invite_3.4.yaml", "scn_invite_3.5.yaml",
        "scn_invite_5.1.1.yaml", "scn_invite_5.1.nat.yaml", "scn_invite_5.2.yaml",
        "scn_invite_5.3.yaml", "scn_invite_5.4.yaml", "scn_invite_5.5.yaml",
        "scn_invite_5.6.yaml", "scn_invite_5.7.0.yaml", "scn_invite_5.7.1.yaml",
        "scn_invite_5.7.2.0.yaml", "scn_invite_5.7.2.1.yaml", "scn_invite_5.7.3.yaml",
        "scn_invite_5.7.4.yaml", "scn_invite_5.7.5.nat.yaml", "scn_invite_5.8.nat.yaml",
        "scn_invite_oo_5.6.yaml", 
        "scn_invite_8.1.yaml", "scn_invite_8.2.yaml", "scn_invite_8.3.yaml",
        "scn_invite_8.4.yaml", "scn_invite_8.5.yaml", "scn_invite_8.6.yaml",
        "scn_invite_10.1.yaml",  
        "register_large_10.3.0.yaml",
        "register_large_10.3.1.yaml", 
        "register_large_10.3.2.proxy.nat.yaml",
        "register_large_10.3.4.proxy.yaml", 
        "register_large_10.3.5.proxy.yaml",
        "register_large_10.3.8.proxy.nat.yaml"]


@pytest.mark.parametrize("scnfile", PARAMS)
def test_siptcp_srcnat_with_proxy(init_test, scn_param_srcnat, rout_192_0_nat, scnfile):
    scnfile = "siptcp/"+scnfile
    scn = replay_data.setup(scnfile, rout_192_0_nat, scn_param_srcnat, None)
    time.sleep(1)
    replay_data.run_scenario(scn)
    replay_data.stop()


