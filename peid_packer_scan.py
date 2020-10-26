"""
Author of this code work, Tsubasa Kuwabara. c FFRI Security, Inc. 2020
"""

from pypeid import PEiDScanner
import os
import json
from util import *

scanner = PEiDScanner()


def is_pypeid_packingdata_detectable(path, result):
    label = os.path.basename(os.path.dirname(path))
    label = label.replace("Yoda`s Crpyter", "Yoda's Crypter")
    label = label.replace("Yoda's ", "yodas_")

    if "PEiD" not in result:
        return (False, [label])

    detectable_bool = False
    for peid in result["PEiD"]:
        if label.lower() in peid.lower():
            detectable_bool = True
            break

    return (detectable_bool, [label])


def is_pypeid_rcelab_detectable(path, result):
    label = os.path.basename(os.path.dirname(path))
    if "ZProtect 1.4.4.0/UnPackMe2" in path or "ZProtect 1.4.4.0/UnPackMe1" in path:
        label = "ZProtect"
    label = label.replace("Yoda ", "yodas_")

    json_data = {}
    with open("rce_label_convert.json", "r") as f:
        json_data = json.load(f)

    replace_bool = False
    for i in json_data:
        if i in label and "peid" in json_data[i]:
            label = json_data[i]["peid"]
            replace_bool = True
            break

    if not replace_bool:
        new_label = ""
        for i in range(len(label.split(" ")) - 1):
            new_label += label.split(" ")[i] + " "
        if len(label.split(" ")) <= 1:
            new_label = label + " "
        label = new_label[:-1]

    no_space_label = label.replace(" ", "")
    under_line_label = label.replace(" ", "_")
    if "PEiD" not in result:
        return (False, [no_space_label, under_line_label])

    detectable_bool = False
    for peid in result["PEiD"]:
        if (
            no_space_label.lower() in peid.lower()
            or under_line_label.lower() in peid.lower()
        ):
            detectable_bool = True
            break

    return (detectable_bool, [no_space_label, under_line_label])


def is_detectable(path, dataset_name, result):
    if dataset_name == "PackingData":
        return is_pypeid_packingdata_detectable(path, result)
    elif dataset_name == "RCE_Lab":
        return is_pypeid_rcelab_detectable(path, result)
    else:
        return (False, [])


def scan_file_recursive(path, dataset_name, json_result):
    for name in os.listdir(path):
        new_path = os.path.join(path, name)
        if os.path.isdir(new_path):
            scan_file_recursive(new_path, dataset_name, json_result)
        else:
            if ".exe" in new_path.lower() or ".dll" in new_path.lower():
                result = scanner.scan_file(new_path)
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
            os.path.join("result/pypeid/", dataset_name, name + ".json"), "w"
        ) as f:
            json.dump(json_result, f, indent=4)
        print("create json: " + new_path + ".json")


def main():
    scan("dataset/PackingData", "PackingData")
    extract_file_recursive("dataset/UnpackMe/")
    scan("dataset/UnpackMe", "RCE_Lab")


if __name__ == "__main__":
    main()
