Required Files
----------------------------------
basic_rtsp_flows.yaml
rtsp_routing.yaml

========================================
           1. Basic
========================================
1.1  RTSP basic flow  
---------------------
file: rtsp.yaml                               
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |

1.2 RTSP basic flow with RTP and RTCP
--------------------------------------------------
file: rtsp_complete.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |
   |    ---- RTCP   ---->    |


========================================
           2. RTP cases
========================================

2.1 RTSP basic flow with first rtp from client
---------------------------------------
file:rtsp_rtp_client.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    ---- RTP    ---->    |


2.2 RTSP basic flow with first rtp from server
----------------------------------------------------
file:rtsp_rtp_server.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |



2.3 no source-port in 200 OK
----------------------------
file:rtsp_rtp_server.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
NOTE: The rtp predict conversion should fail
because the server -> client rtp predict must
be merged with client -> server predict



========================================
          3. RTCP port cases
========================================

3.1 RTCP port not in SETUP but in 200 OK
---------------------------------------
file:rtsp_rtcp_0_1.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |     no rtcp port        |
   |                         |
   |    <--- 200 OK -----    |
   |     rtp / rtcp port     |
   |                         |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    ---- RTCP   ---->    |


3.2 RTCP port in SETUP but not in 200 OK
---------------------------------------
file:rtsp_rtcp_1_0.yaml
client                     server                 
   |    ---- SETUP ----->    |  
   |     rtp/rtcp ports      |
   |                         |
   |    <--- 200 OK -----    |
   |      no rtcp port       |
   |                         |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |   # server sends rtcp to client


3.3 RTCP port not in SETUP and not in 200 OK
-------------------------------------------
file:rtsp_rtcp_0_0.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |     no rtcp port        |
   |                         |
   |    <--- 200 OK -----    |
   |      no rtcp port       |
   |                         |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    ---- RTCP   ---->    |   # client can send rtcp


3.4 Non standard RTCP port in SETUP
---------------------------------------------------
file:rtsp_rtcp_non_std_clnt.yaml
client                     server                 
   |    ---- SETUP ----->    |    # rtcp port is not rtp+1
   |    <--- 200 OK -----    |
   |    <--- RTCP   -----    |



3.5 Non standard RTCP port in 200 OK
---------------------------------------------------
file:rtsp_rtcp_non_std_srvr.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |    # rtcp port is not rtp+1
   |    ---- RTCP   ---->    |



========================================
           4. source field cases
========================================


4.1 source in 200 OK is a third party address, first RTP from server
-------------------------------------------------------------------
file:rtsp_source_3party.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |
   |    ---- RTCP   ---->    |


4.2. source in 200 OK is server address, first RTP from server
-------------------------------------------------------------------
file:rtsp_source_server.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |
   |    ---- RTCP   ---->    |




========================================
       5. destination field cases
========================================

5.1 destination in SETUP is a third party address, first RTP from server
-------------------------------------------------------------------
file:rtsp_source_3party.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |
   |    ---- RTCP   ---->    |


5.2. destination in SETUP is client  address, first RTP from server
-------------------------------------------------------------------
file:rtsp_source_server.yaml
client                     server                 
   |    ---- SETUP ----->    |
   |    <--- 200 OK -----    |
   |    <--- RTP    -----    |
   |    ---- RTP    ---->    |
   |    <--- RTCP   -----    |
   |    ---- RTCP   ---->    |



========================================
         6.  mode field cases
========================================

6.1 mode=record in both SETUP and 200 OK
-----------------------------------------
file:rtsp_mode_record_case_1.yaml


6.2 mode=record in 200 OK but not in SETUP
------------------------------------------
file:rtsp_mode_record_case_2.yaml


6.3 mode=record in SETUP but not in 200 OK
------------------------------------------
file:rtsp_mode_record_case_3.yaml


