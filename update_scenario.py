#!/usr/bin/python


# update scenario from previous version

import argparse
import ruamel.yaml as yaml

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="convert format")
    parser.add_argument('-i', '--input', help='File in old format')
    parser.add_argument('-o', '--output', help='File in new format') 
    args=parser.parse_args()

    with open(args.input, 'r') as f:
        scenario_old = yaml.safe_load(f)

    scenario_new = {"flows":{}, "scenario":[]}

    for fl in scenario_old["flows"]:
        flname = fl["name"]
        del fl["name"]
        print (flname)
        scenario_new["flows"][flname] = fl

    for sn in scenario_old["scenario"]:
        sn_name = sn["action"]
        del sn["action"]
        if "type" in sn:
            del sn["type"]
        if "timeout" in sn:
            tout = sn["timeout"]
            del sn["timeout"]
            scenario_new["scenario"].append ({"delay":{'timeout':tout}})
        if "exec" in sn:
            for i, str in enumerate(sn["exec"]):
                sn["exec"][i] = str.replace("IP","pkt").replace("TCP","pkt")

        scenario_new["scenario"].append ({sn_name:sn})
        
    print (args.output)
    with open(args.output, 'w') as f:
        yaml.dump(scenario_new, f, Dumper=yaml.RoundTripDumper)




