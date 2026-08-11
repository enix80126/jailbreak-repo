#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, hashlib, tarfile, bz2, io, json

def get_hashes(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def extract_control(deb_path):
    with open(deb_path, 'rb') as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError("Not a valid deb file")
        while True:
            header = f.read(60)
            if len(header) < 60: break
            name = header[0:16].decode('ascii').strip()
            size = int(header[48:58].decode('ascii').strip())
            padded = size + (size % 2)
            if name.startswith('control.tar'):
                data = f.read(size)
                ext = name.split('.')[-1] if '.' in name[11:] else ''
                if ext == 'zst':
                    try:
                        import zstandard
                        dctx = zstandard.ZstdDecompressor()
                        data = dctx.decompress(data)
                        mode = "r"
                    except ImportError:
                        raise ImportError("zstandard module is required to extract .zst deb files. Please run 'pip install zstandard'")
                else:
                    mode = f"r:{ext}" if ext in ('gz','xz','bz2') else "r"
                with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tar:
                    for m in tar.getmembers():
                        if m.name.endswith('control') and m.isfile():
                            cf = tar.extractfile(m)
                            if cf: return cf.read().decode('utf-8', errors='replace')
                break
            else:
                f.seek(padded, os.SEEK_CUR)
    raise ValueError("control not found")

def main():
    repo = os.path.dirname(os.path.abspath(__file__))
    debs_dir = os.path.join(repo, 'debs')
    if not os.path.isdir(debs_dir):
        print("No debs/ directory found."); return

    debs = sorted(f for f in os.listdir(debs_dir) if f.endswith('.deb'))
    print(f"Found {len(debs)} deb(s).")

    # For integrity check: track package IDs
    scanned_packages = {}

    entries = []
    for deb in debs:
        path = os.path.join(debs_dir, deb)
        print(f"  {deb}")
        try:
            ctrl = extract_control(path)
            size, md5, sha1, sha256 = get_hashes(path)
            lines = ctrl.strip().replace('\r\n','\n').replace('\r','\n').split('\n')
            
            # Parse control fields
            ctrl_dict = {}
            current_key = None
            for l in lines:
                if l.startswith(' ') or l.startswith('\t'):
                    if current_key:
                        ctrl_dict[current_key] += "\n" + l
                else:
                    if ':' in l:
                        parts = l.split(':', 1)
                        current_key = parts[0].strip()
                        ctrl_dict[current_key] = parts[1].strip()
                    else:
                        current_key = None

            # 1. Read Architecture and Name
            arch_val = "iphoneos-arm64"  # Default fallback
            name_val = ""
            name_line_idx = -1
            
            for idx, l in enumerate(lines):
                if l.startswith('Architecture:'):
                    arch_val = l[13:].strip()
                elif l.startswith('Name:'):
                    name_val = l[5:].strip()
                    name_line_idx = idx

            # 2. Define the correct tags and wrong tags to replace based on architecture
            if arch_val == 'iphoneos-arm64e':
                correct_tag = 'RootHide'
            elif arch_val == 'iphoneos-arm64':
                correct_tag = 'Rootless'
            elif arch_val == 'iphoneos-arm':
                correct_tag = 'Rootful'
            else:
                correct_tag = ''

            # 3. Integrity / Health Checks
            # Helper for case-insensitive lookup
            def get_field(key_name, default=''):
                for k, v in ctrl_dict.items():
                    if k.lower() == key_name.lower():
                        return v
                return default

            pkg_id = get_field('Package').strip()
            pkg_version = get_field('Version').strip()
            pkg_desc = get_field('Description').strip()

            # Check required fields
            missing_fields = []
            for field in ['Package', 'Version', 'Architecture', 'Description']:
                if not get_field(field).strip():
                    missing_fields.append(field)
            if missing_fields:
                print(f"    [警告] 缺少关键控制字段: {', '.join(missing_fields)}")

            # Check duplicate package IDs
            if pkg_id:
                if pkg_id in scanned_packages:
                    prev_deb, prev_ver = scanned_packages[pkg_id]
                    print(f"    [警告] 发现重复的 Package ID '{pkg_id}':")
                    print(f"           - 当前包: {deb} (版本: {pkg_version})")
                    print(f"           - 冲突包: {prev_deb} (版本: {prev_ver})")
                else:
                    scanned_packages[pkg_id] = (deb, pkg_version)

            # Check Depends field parentheses match
            depends_val = get_field('Depends').strip()
            if depends_val:
                if depends_val.count('(') != depends_val.count(')'):
                    print(f"    [警告] Depends 依赖字段括号不匹配: '{depends_val}'")

            # 4. Rebuild lines with updated Name
            has_original_dep = any(k.lower() in ('sileodepiction', 'depiction') for k in ctrl_dict)
            exclude_fields = ['filename:', 'size:', 'md5sum:', 'sha1:', 'sha256:']
            if not has_original_dep:
                exclude_fields.extend(['sileodepiction:', 'depiction:'])

            out = []
            final_name_val = name_val or pkg_id
            for idx, l in enumerate(lines):
                lower_l = l.lower()
                if any(lower_l.startswith(x) for x in exclude_fields):
                    continue
                if idx == name_line_idx and correct_tag:
                    import re
                    # Strip any old roothide, rootless, or rootful tags ONLY at the end of the string ($)
                    pattern = r'[\s\-_\(\[\（\【]*(roothide|rootless|rootful)[\s\)\}\]）】]*$'
                    cleaned_name = re.sub(pattern, '', name_val, flags=re.IGNORECASE)
                    # Clean up any trailing space/dash/brackets left over
                    cleaned_name = re.sub(r'[\s\-_\(\[\（\【]+$', '', cleaned_name)
                    # Append the correct unified tag format
                    final_name_val = f"{cleaned_name} ({correct_tag})"
                    l = f"Name: {final_name_val}"
                out.append(l)

            # 5. Generate Sileo Native Depiction JSON (1:1 Banyungong Style)
            if pkg_id:
                # Calculate file size in MB/KB
                if size >= 1024 * 1024:
                    size_str = f"{size / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{size / 1024:.2f} KB"

                # Get file modification time
                import datetime
                mtime = os.path.getmtime(path)
                update_time = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

                # Parse iOS compatibility from Depends
                import re
                min_fw = re.search(r'firmware\s*\(\s*>=\s*([\d\.]+)\s*\)', depends_val)
                max_fw = re.search(r'firmware\s*\(\s*<=\s*([\d\.]+)\s*\)', depends_val)
                if min_fw and max_fw:
                    fw_range = f"{min_fw.group(1)} ~ {max_fw.group(1)}"
                elif min_fw:
                    fw_range = f"{min_fw.group(1)} ~ 18.2"
                elif max_fw:
                    fw_range = f"<= {max_fw.group(1)}"
                else:
                    fw_range = "全部兼容"

                # Extract Changelog field
                changelog_text = get_field('Changelog', get_field('Changes', '')).strip()
                if not changelog_text:
                    changelog_text = f"#### 版本 {pkg_version}\n\n该版本暂无详细的更新说明。"

                dep_views = [
                    {
                        "class": "DepictionLabelView",
                        "text": "插件介绍",
                        "fontWeight": "bold",
                        "fontSize": 19,
                        "usePadding": True,
                        "useMargins": True,
                        "margins": "{10,0,8,0}"
                    },
                    {
                        "class": "DepictionMarkdownView",
                        "markdown": pkg_desc,
                        "useSpacing": False
                    },
                    {
                        "class": "DepictionSeparatorView"
                    },
                    {
                        "class": "DepictionLabelView",
                        "text": "版本详细说明",
                        "fontWeight": "semibold",
                        "fontSize": 16,
                        "usePadding": True,
                        "useMargins": True,
                        "margins": "{10,0,8,0}"
                    },
                    # 1:1 Banyungong 2-Column Grid Table via horizontal stack views
                    {
                        "class": "DepictionStackView",
                        "orientation": "landscape",
                        "views": [
                            {
                                "class": "DepictionStackView",
                                "views": [
                                    {
                                        "class": "DepictionLabelView",
                                        "text": "插件版本",
                                        "textColor": "#8e8e93",
                                        "margins": "{16,0,8,0}"
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": pkg_version,
                                        "fontWeight": "semibold",
                                        "fontSize": 16,
                                        "usePadding": False
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": "插件大小",
                                        "textColor": "#8e8e93",
                                        "margins": "{16,0,8,0}"
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": size_str,
                                        "fontWeight": "semibold",
                                        "fontSize": 16,
                                        "usePadding": False
                                    }
                                ]
                            },
                            {
                                "class": "DepictionStackView",
                                "views": [
                                    {
                                        "class": "DepictionLabelView",
                                        "text": "插件更新时间",
                                        "textColor": "#8e8e93",
                                        "margins": "{16,0,8,0}"
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": update_time,
                                        "fontWeight": "semibold",
                                        "fontSize": 16,
                                        "usePadding": False
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": "插件系统兼容",
                                        "textColor": "#8e8e93",
                                        "margins": "{16,0,8,0}"
                                    },
                                    {
                                        "class": "DepictionLabelView",
                                        "text": fw_range,
                                        "fontWeight": "semibold",
                                        "fontSize": 16,
                                        "usePadding": False
                                    }
                                ]
                            }
                        ]
                    }
                ]


                depiction_data = {
                    "class": "DepictionTabView",
                    "minVersion": "0.1",
                    "tabs": [
                        {
                            "tabname": "插件介绍",
                            "class": "DepictionStackView",
                            "views": dep_views
                        },
                        {
                            "tabname": "更新日志",
                            "class": "DepictionStackView",
                            "views": [
                                {
                                    "class": "DepictionLabelView",
                                    "text": "更新历史说明",
                                    "fontWeight": "semibold",
                                    "fontSize": 16,
                                    "usePadding": True,
                                    "useMargins": True,
                                    "margins": "{10,0,8,0}"
                                },
                                {
                                    "class": "DepictionMarkdownView",
                                    "markdown": changelog_text,
                                    "useSpacing": False
                                }
                            ]
                        }
                    ]
                }

                dep_dir = os.path.join(repo, 'depictions')
                if not os.path.exists(dep_dir):
                    os.makedirs(dep_dir)

                dep_path = os.path.join(dep_dir, f"{pkg_id}.json")
                new_json = json.dumps(depiction_data, indent=2, ensure_ascii=False)

                # Avoid redundant writing if the depiction file hasn't changed
                should_write = True
                if os.path.exists(dep_path):
                    try:
                        with open(dep_path, 'r', encoding='utf-8') as f_read:
                            if f_read.read().strip() == new_json.strip():
                                should_write = False
                    except Exception:
                        pass

                if should_write:
                    with open(dep_path, 'w', encoding='utf-8') as f_write:
                        f_write.write(new_json)

            import urllib.parse
            encoded_deb = urllib.parse.quote(deb)
            # Disable custom SileoDepiction injection to allow Sileo native UI multi-source aggregation
            # if pkg_id and not has_original_dep:
            #     out.append(f"SileoDepiction: https://enix80126.github.io/jailbreak-repo/depictions/{pkg_id}.json")
            
            out += [f"Filename: https://enix80126.github.io/jailbreak-repo/debs/{encoded_deb}", f"Size: {size}",
                    f"MD5sum: {md5}", f"SHA1: {sha1}", f"SHA256: {sha256}"]
            entries.append('\n'.join(out))
        except Exception as e:
            print(f"  ERROR: {e}")

    data = ('\n\n'.join(entries) + '\n').encode('utf-8')
    open(os.path.join(repo, 'Packages'), 'wb').write(data)
    open(os.path.join(repo, 'Packages.bz2'), 'wb').write(bz2.compress(data))
    print(f"Done: {len(entries)} packages written.")

if __name__ == '__main__':
    main()
