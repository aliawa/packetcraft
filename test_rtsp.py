import replay_data
import pytest
import logging
import glob

root_dir = "/home/aawais/packetcraft/rtsp_tests/"



@pytest.fixture(scope='module')
def init_test():
    replay_data.setup_logging(logging.WARN)

@pytest.fixture(scope="module")
def rout_192_0_nat():
    return root_dir + "routing_192_1.yaml"

PARAMS = [
        "rtsp.yaml",
        "rtsp_complete.yaml",
        "rtsp_destination_3party.yaml",
        "rtsp_destination_client.yaml",
        "rtsp_mode_record_case_1.yaml",
        "rtsp_mode_record_case_2.yaml",
        "rtsp_mode_record_case_3.yaml",
        "rtsp_multicast.yaml",
        "rtsp_rtcp_0_0.yaml",
        "rtsp_rtcp_0_1.yaml",
        "rtsp_rtcp_1_0.yaml",
        "rtsp_rtcp_non_std_clnt.yaml",
        "rtsp_rtcp_non_std_srvr.yaml",
        "rtsp_rtp_client.yaml",
        "rtsp_rtp_no_src.yaml",
        "rtsp_rtp_no_src_1.yaml",
        "rtsp_rtp_no_src_2.yaml",
        "rtsp_rtp_server.yaml",
        "rtsp_source_3party.yaml",
        "rtsp_source_server.yaml"]

       # "rtsp_rtp_no_src_dst_nat.yaml",

@pytest.mark.parametrize("scnfile", PARAMS)
def test_rtsp(init_test, rout_192_0_nat, scnfile):
    scnfile = "rtsp_tests/"+scnfile
    scn = replay_data.setup(scnfile, rout_192_0_nat, None, None)
    time.sleep(1)
    replay_data.run_scenario(scn)
    replay_data.stop()


