# Evaluation of packer type estimation/detection tools

We evaluated two packer type estimation/detection tools ([pypeid](https://github.com/FFRI/pypeid) and [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy)) to fix [this issue](https://github.com/FFRI/ffridataset-scripts/issues/1).

## Summary

DIE can detect packed binaries and estimate the type of packer with high precision compared with pypeid. However, the detection coverage of DIE is slightly lower than pypeid. See [results](#Results) for more details.

## Dataset used for evaluation

We use two datasets for evaluating packer type estimation/detection tools.

- [PackingData](https://github.com/chesvectain/PackingData)
- [RCE\_Lab](https://github.com/apuromafo/RCE_Lab)

### PackingData

This dataset contains both packed and normal (i.e., non-packed) binaries, which are used in the paper titled ["All-in-One Framework for Detection, Unpacking, and Verification for Malware Analysis."](https://www.hindawi.com/journals/scn/2019/5278137/) Since it contains both packed and normal binaries, we use it for the performance evaluation of both the packer type estimation and detection.

**Specification**

- It contains 458 normal binaries.
- It contains 2469 packed binaries.
    - These binaries are created by packing 130 PE files using the following 19 packers (but 129 PE files for JDPack):
        - ASPack, BeRoEXEPacker, FSG, JDpack, MEW, MPRESS, Molebox, NSPack, Neolite, PECompact, Petite, Packman, RLPack, UPX, WinUpack, Yoda’s Crypter, Yoda’s Protector, eXpressor, exe32pack

**Notes about PackingData dataset (2021/03/11)**

We noticed that PackingData dataset contains some mislabeled samples after publishing the [first evaluation result](https://github.com/FFRI/PackerDetectionToolEvaluation/tree/ae0f653ade67e5e0d9d0d7d996dd9816e09a1a3c).
(For example, `PackingData/Notpacked/avs_check_x86.exe` is [an UPX packed-binary](https://www.virustotal.com/gui/file/2fd27a3f6c9644b8105c7934d0f41fe10b056e327491df37750d634336f4b2db/details), but labeled as `NotPacked`.)

So, we changed the labels of some samples for the precise evaluation.
To fix the labeles of mislabeled samples, please run [change\_dataset\_labels.py](./change_dataset_labels.py) script.

TPRs and FPRs slightly differs from the previous result, but the [conclusion does not change](#summary).

### RCE\_Lab

This dataset contains binaries packed by various different packers. We only use the binaries in `tuts4you/Unpack*` for evaluation. Since this dataset does not contain normal binaries, we mainly use it for evaluating the performance of packer type estimation.

## Results

### PackingData

The following table shows the comparison of packer type estimation performance between pypeid and DIE. You can see the DIE's improvement of estimation performance to pypeid.

|     | pypeid | DIE   |
| --- | -----: | ----: |
| Accuracy | 73.2%  | **84.9%** |

The following table shows the comparison of packer detection performance between pypeid and DIE. You can see the great reduction of FPR for DIE compared with pypeid.

|     | pypeid | DIE   |
| --- | -----: | ----: |
| TPR | 94.5%  | 93.5% |
| FPR | **54.8%**  | **0.7%** |

### RCE\_Lab

The following table shows the comparison of packer type estimation performance between pypeid and DIE. You can also see the improvement of estimation performance in this dataset.

|      | pypeid | DIE   |
| ---- | -----: | ----: |
| Accuracy  | 65.1%  | **69.0%** |

The following table shows the comparison of packer detection performance between pypeid and DIE. We do not show the FPR because this dataset does not contain normal binaries. The packer detection performance of DIE is slight lower than pypeid.

|     | pypeid |  DIE  |
| --- | -----: | ----: |
| TPR | 88.2%  | 83.1% |

## How to reproduce the results?

### Tested platform

- Ubuntu 20.04 LTS on WSL on Windows 10 version 1909

### Requirements

- Python 3.6
- [Poetry](https://python-poetry.org/)

### Prepare dataset

```
$ git clone --depth=1 https://github.com/chesvectain/PackingData.git dataset/PackingData
$ git clone --depth=1 https://github.com/apuromafo/RCE_Lab.git
$ mkdir dataset/UnpackMe
$ mv RCE_Lab/tuts4you/Unpack* dataset/UnpackMe
$ python change_dataset_labels.py
```

### Resolve dependencies

```
$ sudo apt install unrar # To resolve rarfile's dependencies manually
$ poetry shell
$ poetry update
```

### Scan with pypeid

```
$ python peid_packer_scan.py
$ python peid_packer_scan_statistics.py
PackingData
- PackingData.json
  - Total: 2476
    - Scan-failed samples: 0
    - Samples scanned: 2476
       - Purely detected as packed: 129
       - Excessively detected as packed (containing true label): 1810
       - Purely detected as non-packed: 137
       - Excessively detected as packed (not containing true label): 400
- Notpacked.json
  - Total: 451
    - Scan-failed samples: 0
    - Samples scanned: 451
       - Purely detected as packed: 0
       - Excessively detected as packed (containing true label): 0
       - Purely detected as non-packed: 204
       - Excessively detected as packed (not containing true label): 247
Categorical Accuracy:  0.7321489579774513
TPR:  0.9446688206785138
FPR:  0.5476718403547672
...
```

### Scan with DIE

```
$ wget https://github.com/horsicq/DIE-engine/releases/download/3.00/die_lin64_portable_3.00.tar.gz
$ mkdir die_lin64_portable_3.00
$ tar -zxvf die_lin64_portable_3.00.tar.gz -C die_lin64_portable_3.00
$ python die_packer_scan.py
$ python die_packer_scan_statistics.py
PackingData
- PackingData.json
  - Total:  2476
    - Scan-failed samples: 0
    - Samples scanned: 2476
       - Purely detected as packed: 2037
       - Excessively detected as packed (containing true label): 146
       - Purely detected as non-packed: 161
       - Excessively detected as packed (not containing true label): 132
- Notpacked.json
  - Total:  451
    - Scan-failed samples: 0
    - Samples scanned: 451
       - Purely detected as packed: 0
       - Excessively detected as packed (containing true label): 0
       - Purely detected as non-packed: 448
       - Excessively detected as packed (not containing true label): 3
Categorical Accuracy:  0.8489921421250427
TPR:  0.9349757673667205
FPR:  0.0066518847006651885
...
```

## Scan results format

You can get the scan result as JSON arrays. Each element of this JSON arrays is as follows.

```
{
  "path": The location where the target executable file at the time of judgment existed,
  "name": The name of the target executable file,
  "scan": Judgment result,
  "detectable": Success or failure of packer type judgment
  "feature": [
    Label of the target executable file
  ]
}
```

## Author

Tsubasa Kuwabara. © FFRI Security, Inc. 2020

## License

[Apache version 2.0](./LICENSE)
