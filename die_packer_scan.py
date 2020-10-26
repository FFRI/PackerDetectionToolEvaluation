"""
Author of this code work, Tsubasa Kuwabara. c FFRI Security, Inc. 2020
"""

import subprocess
import os
import shutil
import json
from util import *

CWD_DIR = os.getcwd()


def is_die_packingdata_detectable(path, result):
    label = os.path.basename(os.path.dirname(path))
    label = label.replace("WinUpack", "(Win)Upack")
    label = label.replace("BeRoEXEPacker", "BeRo")
    label = label.replace("Yoda`s Crpyter", "Yoda's Crypter")

    if "detects" not in result:
        return (False, [label])

    detects = result["detects"]
    protector_list = []
    for i in detects:
        if (
            "type" not in i
            or "string" not in i
            or (i["type"] != "protector" and i["type"] != "packer")
        ):
            continue
        protector_list.append(i["string"])

    if len(protector_list) <= 0:
        return (False, [label])

    detectable_bool = False
    for protector in protector_list:
        if label.lower() in protector.lower():
            detectable_bool = True
            break

    return (detectable_bool, [label])


def is_die_rcelab_detectable(path, result):
    label = os.path.basename(os.path.dirname(path))
    if "ZProtect 1.4.4.0/UnPackMe2" in path or "ZProtect 1.4.4.0/UnPackMe1" in path:
        label = "ZProtect"
    label = label.replace("dot", ".")

    json_data = {}
    with open(os.path.join(CWD_DIR, "rce_label_convert.json"), "r") as f:
        json_data = json.load(f)

    replace_bool = False
    for i in json_data:
        if i in label and "die" in json_data[i]:
            label = json_data[i]["die"]
            replace_bool = True
            break

    if not replace_bool:
        new_label = ""
        for i in range(len(label.split(" ")) - 1):
            new_label += label.split(" ")[i] + " "
        if len(label.split(" ")) <= 1:
            new_label = label + " "
        label = new_label[:-1]

    detects = result["detects"]
    protector_list = []
    for i in detects:
        if (
            "type" not in i
            or "string" not in i
            or (i["type"] != "protector" and i["type"] != "packer")
        ):
            continue
        protector_list.append(i["string"])

    if len(protector_list) <= 0:
        return (False, [label])

    detectable_bool = False
    for protector in protector_list:
        if label.lower() in protector.lower():
            detectable_bool = True
            break

    return (detectable_bool, [label])


def is_detectable(path, dataset_name, result):
    if dataset_name == "PackingData":
        return is_die_packingdata_detectable(path, result)
    elif dataset_name == "RCE_Lab":
        return is_die_rcelab_detectable(path, result)
    else:
        return (False, [])


def scan_file_recursive(path, dataset_name, json_result):
    for name in os.listdir(path):
        new_path = os.path.join(path, name)
        if os.path.isdir(new_path):
            scan_file_recursive(new_path, dataset_name, json_result)
        else:
            if ".exe" in new_path.lower() or ".dll" in new_path.lower():
                tmp_path = os.path.join(CWD_DIR, "test.exe")
                shutil.copy(new_path, tmp_path)
                result = subprocess.check_output(["./diec.sh", "-j", tmp_path])
                os.remove(tmp_path)
                result = json.loads(result)
                detectable_bool, label_list = is_detectable(
                    new_path, dataset_name, result
                )
                json_result.append(
                    {
                        "path": os.path.dirname(new_path),
                        "name": os.path.basename(new_path),
                        "scan": result,
                        "detectable": detectable_bool,
                        "labels": label_list,
                    }
                )


def scan(path, dataset_name):
    for name in os.listdir(path):
        new_path = os.path.join(path, name)
        if not os.path.isdir(new_path):
            continue

        if ".git" in name:
            continue

        print(new_path)
        json_result = []
        scan_file_recursive(new_path, dataset_name, json_result)
        with open(
            os.path.join(CWD_DIR, "result/die/", dataset_name, name + ".json"), "w"
        ) as f:
            json.dump(json_result, f, indent=4)
        print("create json: " + new_path + ".json")


def main():
    os.chdir("die_lin64_portable_3.00/die_lin64_portable/")
    path = os.path.join(CWD_DIR, "dataset/PackingData/")
    scan(path, "PackingData")
    path = os.path.join(CWD_DIR, "dataset/UnpackMe/")
    extract_file_recursive(path)
    scan(path, "RCE_Lab")


if __name__ == "__main__":
    main()
