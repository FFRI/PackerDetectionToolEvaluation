"""
Author of this code work, Tsubasa Kuwabara. c FFRI Security, Inc. 2020
"""

import json
import os


def parse_jsons(path):
    for name in os.listdir(path):
        count = 0
        detectable_count = 0
        none_count = 0
        many_packer_count = 0
        f = open(os.path.join(path, name), "r")
        json_data = json.load(f)
        f.close()

        for i in json_data:
            count += 1

            if "scan" not in i or "PEiD" not in i["scan"] or "detectable" not in i:
                continue

            if len(i["scan"]["PEiD"]) <= 0:
                none_count += 1
            elif len(i["scan"]["PEiD"]) > 1:
                many_packer_count += 1

            if i["detectable"]:
                detectable_count += 1

        print("- " + name)
        print("  - 全体数: ", count)
        print("  - 検知成功: ", detectable_count)
        print("  - パッカーなし: ", none_count)
        print("  - 複数パッカー検出: ", many_packer_count)


def main():
    print("PackingData")
    parse_jsons("result/pypeid/PackingData")

    print()

    print("RCE_Lab")
    parse_jsons("result/pypeid/RCE_Lab")


if __name__ == "__main__":
    main()
