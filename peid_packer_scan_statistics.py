"""
Author of this code work, Tsubasa Kuwabara. c FFRI Security, Inc. 2020
"""

import json
import sys
import os


def show_type_estimation_performance(results):
    n_total = sum(i["n_samples"] for i in results.values())
    n_purely_detected = sum(
        i["detectable"]["purely"] + i["detectable"]["excessively"]
        if i["label"] == "packed"
        else i["non_detectable"]["purely"]
        for i in results.values()
    )
    print("Categorical Accuracy: ", n_purely_detected / n_total)


def show_detection_performance(results):
    contains_nonpacked = False
    for i in results.values():
        if i["label"] == "non_packed":
            contains_nonpacked = True

    n_packed = sum(i["n_samples"] for i in results.values() if i["label"] == "packed")
    tp = sum(
        i["detectable"]["purely"]
        + i["detectable"]["excessively"]
        + i["non_detectable"]["excessively"]
        for i in results.values()
        if i["label"] == "packed"
    )
    print("TPR: ", tp / n_packed)

    if contains_nonpacked:
        n_nonpacked = sum(
            i["n_samples"] for i in results.values() if i["label"] == "non_packed"
        )
        fp = sum(
            i["non_detectable"]["excessively"]
            for i in results.values()
            if i["label"] == "non_packed"
        )
        print("FPR: ", fp / n_nonpacked)


def parse_jsons(path):
    results = dict()
    for name in os.listdir(path):
        with open(os.path.join(path, name), "r") as f:
            json_data = json.load(f)

        n_samples_failed = 0
        n_samples_scanned = 0
        purely_detected_as_packed = 0
        excessively_detected_as_packed = 0
        purely_detected_as_non_packed = 0
        non_packed_but_excessively_detected_as_packed = 0
        for i in json_data:
            if "scan" not in i or "PEiD" not in i["scan"] or "detectable" not in i:
                print(f"Scan failed sample", i["path"], file=sys.stderr)
                n_samples_failed += 1
                continue

            n_samples_scanned += 1
            if i["detectable"]:  # Contains true label
                if len(i["scan"]["PEiD"]) > 1:
                    excessively_detected_as_packed += 1
                else:
                    purely_detected_as_packed += 1
            else:  # Does not contain true label
                if len(i["scan"]["PEiD"]) <= 0:
                    purely_detected_as_non_packed += 1
                else:
                    non_packed_but_excessively_detected_as_packed += 1

        print("- " + name)
        print("  - Total:", n_samples_failed + n_samples_scanned)
        print("    - Scan-failed samples:", n_samples_failed)
        print("    - Samples scanned:", n_samples_scanned)
        print("       - Purely detected as packed:", purely_detected_as_packed)
        print(
            "       - Excessively detected as packed (containing true label):",
            excessively_detected_as_packed,
        )
        print("       - Purely detected as non-packed:", purely_detected_as_non_packed)
        print(
            "       - Excessively detected as packed (not containing true label):",
            non_packed_but_excessively_detected_as_packed,
        )

        if name == "Notpacked.json":
            label = "non_packed"
        else:
            label = "packed"

        results[name] = {
            "label": label,
            "n_samples": n_samples_scanned,
            "detectable": {
                "purely": purely_detected_as_packed,
                "excessively": excessively_detected_as_packed,
            },
            "non_detectable": {
                "purely": purely_detected_as_non_packed,
                "excessively": non_packed_but_excessively_detected_as_packed,
            },
        }

    show_type_estimation_performance(results)
    show_detection_performance(results)


def main():
    print("PackingData")
    parse_jsons("result/pypeid/PackingData")

    print()

    print("RCE_Lab")
    parse_jsons("result/pypeid/RCE_Lab")


if __name__ == "__main__":
    main()
