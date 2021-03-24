"""
Author of this code work, Tsubasa Kuwabara. c FFRI Security, Inc. 2020
"""

import os
import zipfile
import rarfile


def extract_file_recursive(path):
    for name in os.listdir(path):
        new_path = os.path.join(path, name)
        if os.path.isdir(new_path):
            extract_file_recursive(new_path)
        else:
            try:
                if ".zip" in new_path:
                    print("unzip: " + new_path)
                    zip_file = zipfile.ZipFile(new_path)
                    zip_file.setpassword("tuts4you")
                    target_dir = new_path[:-4]
                    zip_file.extractall(target_dir)
                    zip_file.close()
                    os.remove(new_path)
                if ".rar" in new_path:
                    print("unrar: " + new_path)
                    rar_file = rarfile.RarFile(new_path)
                    rar_file.setpassword("tuts4you")
                    target_dir = new_path[:-4]
                    rar_file.extractall(target_dir)
                    rar_file.close()
                    os.remove(new_path)
            except Exception as e:
                print("error: " + new_path)
                print(e)
