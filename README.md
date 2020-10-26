# Evaluation of packer type estimation/detection tools

We evaluated two packer type estimation/detection tools ([pypeid](https://github.com/FFRI/pypeid) and [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy)) to fix [this issue](https://github.com/FFRI/ffridataset-scripts/issues/1).

## Summary

DIE can detect packed binaries and estimate the type of packer with high precision compared with pypeid. However, the detection coverage of DIE is slightly lower than pypeid. See [results](#Results) for more details.

## Dataset used for evaluation

We use two datasets for evaluating packer type estimation/detection tools.

- [PackingData](https://github.com/chesvectain/PackingData)
- [RCE_Lab](https://github.com/apuromafo/RCE_Lab)

### PackingData

This dataset contains both packed and normal (i.e., non-packed) binaries, which are used in the paper titled ["All-in-One Framework for Detection, Unpacking, and Verification for Malware Analysis."](https://www.hindawi.com/journals/scn/2019/5278137/) Since it contains both packed and normal binaries, we use it for the performance evaluation of both the packer type estimation and detection.

**Specification**

- It contains 458 normal binaries.
- It contains 2469 packed binaries.
    - These binaries are created by packing 130 PE files using the following 19 packers (but 129 PE files for JDPack):
        - ASPack, BeRoEXEPacker, FSG, JDpack, MEW, MPRESS, Molebox, NSPack, Neolite, PECompact, Petite, Packman, RLPack, UPX, WinUpack, Yoda’s Crypter, Yoda’s Protector, eXpressor, exe32pack

### RCE_Lab

This dataset contains binaries packed by various different packers. We only use the binaries in `tuts4you/Unpack*` for evaluation. Since this dataset does not contain normal binaries, we mainly use it for evaluating the performance of packer type estimation.

## Results

### PackingData

The following table shows the comparison of packer type estimation performance between pypeid and DIE. You can see the DIE's improvement of estimation performance to pypeid.

|     | pypeid | DIE   |
| --- | -----: | ----: |
| TPR | 73.1%  | **89.9%** |
| TPR (for only packed binaries) | 78.4%  | **88.1%** |

The following table shows the comparison of packer detection performance between pypeid and DIE. You can see the great reduction of FPR for DIE compared with pypeid.

|     | pypeid | DIE   |
| --- | -----: | ----: |
| TPR | 94.5%  | 93.5% |
| FPR | **55.5%**  | **0.7%** |

### RCE_Lab

The following table shows the comparison of packer type estimation performance between pypeid and DIE. You can also see the improvement of estimation performance in this dataset.

|      | pypeid | DIE   |
| ---- | -----: | ----: |
| TPR  | 65.0%  | **73.7%** |

The following table shows the comparison of packer detection performance between pypeid and DIE. We do not show the FPR because this dataset does not contain normal binaries. The packer detection performance of DIE is slight lower than pypeid.

|     | pypeid |  DIE  |
| --- | -----: | ----: |
| TPR | 88.1%  | 83.1% |

## How to reproduce the results?

### Prepare dataset

```
$ git clone --depth=1 https://github.com/chesvectain/PackingData.git dataset/PackingData
$ git clone --depth=1 https://github.com/apuromafo/RCE_Lab.git
$ mkdir dataset/UnpackMe
$ mv RCE_Lab/tuts4you/Unpack* dataset/UnpackMe
```

### Scan with pypeid

```
# Install pypeid by referring to the README of the https://github.com/FFRI/pypeid
$ python peid_packer_scan.py
$ python peid_packer_scan_statistics.py
PackingData
- Notpacked.json
  - 全体数:  458
  - 検知成功:  0
  - パッカーなし:  204
  - 複数パッカー検出:  238
- PackingData.json
  - 全体数:  2469
  - 検知成功:  1936
  - パッカーなし:  137
  - 複数パッカー検出:  1815
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
- Notpacked.json
  - 全体数:  458
  - 検知成功:  0
  - パッカーなし:  455
  - 複数パッカー検出:  1
- PackingData.json
  - 全体数:  2469
  - 検知成功:  2176
  - パッカーなし:  160
  - 複数パッカー検出:  135
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
