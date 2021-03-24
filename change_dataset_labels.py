"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2021
"""

import os
import json
import shutil


def _main():
    with open("mislabeled_samples.json", "r") as fin:
        mislabeled_samples = json.loads(fin.read())
    for mislabeled_sample in mislabeled_samples:
        src = mislabeled_sample["src_file"]
        dst = mislabeled_sample["dst_dir"]
        if not os.path.exists(dst):
            os.makedirs(dst)
        shutil.move(src, dst)


if __name__ == "__main__":
    _main()
