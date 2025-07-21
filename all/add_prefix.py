#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量为指定目录下的所有子文件夹添加编号前缀。
一级和二级子文件夹均会编号。
"""
import os
import sys

def add_prefix_to_subfolders(parent_dir):
    """
    给 parent_dir 下所有子文件夹添加编号前缀。
    """
    folders = [f for f in os.listdir(parent_dir) if os.path.isdir(os.path.join(parent_dir, f))]
    folders.sort()
    for idx, folder in enumerate(folders, 1):
        old_path = os.path.join(parent_dir, folder)
        new_name = f"{idx:02d}_{folder}"
        new_path = os.path.join(parent_dir, new_name)
        if not os.path.exists(new_path):
            try:
                os.rename(old_path, new_path)
                print(f"Renamed: {old_path} -> {new_path}")
            except Exception as e:
                print(f"[!] Failed to rename {old_path}: {e}")

if __name__ == "__main__":
    # 默认目录为当前脚本同级的 sorted_templates
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sorted_templates')
    if not os.path.isdir(base_dir):
        print(f"[!] Directory not found: {base_dir}")
        sys.exit(1)
    print(f"[+] Adding prefix to subfolders in: {base_dir}")
    add_prefix_to_subfolders(base_dir)
    # 二级目录
    for folder in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder)
        if os.path.isdir(folder_path):
            add_prefix_to_subfolders(folder_path)
    print("[+] Done.")
