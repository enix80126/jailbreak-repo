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
            pkg_id = ctrl_dict.get('Package', '').strip()
            pkg_version = ctrl_dict.get('Version', '').strip()
            pkg_desc = ctrl_dict.get('Description', '').strip()

            # Check required fields
            missing_fields = []
            for field in ['Package', 'Version', 'Architecture', 'Description']:
                if field not in ctrl_dict or not ctrl_dict[field].strip():
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
            depends_val = ctrl_dict.get('Depends', '').strip()
            if depends_val:
                if depends_val.count('(') != depends_val.count(')'):
                    print(f"    [警告] Depends 依赖字段括号不匹配: '{depends_val}'")

            # 4. Rebuild lines with updated Name
            out = []
            final_name_val = name_val or pkg_id
            for idx, l in enumerate(lines):
                lower_l = l.lower()
                if any(lower_l.startswith(x) for x in ['filename:','size:','md5sum:','sha1:','sha256:','sileodepiction:','depiction:']):
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

            # 5. Generate Sileo HTML Depiction (1:1 Banyungong Style)
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
                js_min_fw = min_fw.group(1) if min_fw else "11.0"
                js_max_fw = max_fw.group(1) if max_fw else "99.0"

                if min_fw and max_fw:
                    fw_range = f"{min_fw.group(1)} ~ {max_fw.group(1)}"
                elif min_fw:
                    fw_range = f"{min_fw.group(1)} ~ 18.2"
                elif max_fw:
                    fw_range = f"<= {max_fw.group(1)}"
                else:
                    fw_range = "全部兼容"

                # Extract Changelog field
                changelog_text = ctrl_dict.get('Changelog', ctrl_dict.get('Changes', '')).strip()
                if not changelog_text:
                    changelog_text = f"<h4>版本 {pkg_version}</h4><p>该版本暂无详细的更新说明。</p>"
                else:
                    # Convert simple markdown list to HTML
                    changelog_html = ""
                    for line in changelog_text.split('\n'):
                        line = line.strip()
                        if line.startswith('- ') or line.startswith('* '):
                            changelog_html += f"<li>{line[2:]}</li>"
                        elif line.startswith('### '):
                            changelog_html += f"<h3>{line[4:]}</h3>"
                        elif line.startswith('#### '):
                            changelog_html += f"<h4>{line[5:]}</h4>"
                        elif line:
                            changelog_html += f"<p>{line}</p>"
                    changelog_text = f"<ul>{changelog_html}</ul>" if "<li>" in changelog_html else changelog_html

                # 1:1 Banyungong HTML Template
                html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="color-scheme" content="light dark">
    <title>{final_name_val}</title>
    <style>
        :root {{
            --bg-color: #f2f2f7;
            --card-color: #ffffff;
            --text-color: #000000;
            --secondary-text-color: #8e8e93;
            --separator-color: #e5e5ea;
            --tint-color: #30b0c4;
            --banner-bg: #4fb3bf;
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-color: #0c0c0e;
                --card-color: #1c1c1e;
                --text-color: #ffffff;
                --secondary-text-color: #8e8e93;
                --separator-color: #2c2c2e;
                --tint-color: #30b0c4;
                --banner-bg: #2b9eb3;
            }}
        }}

        * {{
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Icons", "Helvetica Neue", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            font-size: 15px;
            line-height: 1.4;
        }}

        /* Header Image with Purple Tech Gradient */
        .top-banner {{
            width: 100%;
            height: 120px;
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #db2777 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: bold;
            font-size: 20px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
            letter-spacing: 2px;
        }}

        .container {{
            padding: 16px;
        }}

        /* Package Main Header block */
        .pkg-header {{
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            background-color: var(--card-color);
            padding: 14px;
            border-radius: 12px;
        }}

        .pkg-icon {{
            width: 60px;
            height: 60px;
            border-radius: 14px;
            margin-right: 14px;
            object-fit: cover;
            background-color: #f0f0f0;
        }}

        .pkg-header-info {{
            flex: 1;
        }}

        .pkg-name {{
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 4px 0;
            color: var(--text-color);
        }}

        .pkg-author {{
            font-size: 14px;
            color: var(--secondary-text-color);
            margin: 0;
        }}

        .btn-get {{
            background-color: var(--tint-color);
            color: #ffffff;
            font-weight: bold;
            border: none;
            padding: 6px 16px;
            border-radius: 16px;
            font-size: 14px;
            cursor: pointer;
        }}

        /* Tabs Section */
        .tabs {{
            display: flex;
            border-bottom: 1px solid var(--separator-color);
            margin-bottom: 16px;
        }}

        .tab {{
            flex: 1;
            text-align: center;
            padding: 12px 0;
            font-size: 15px;
            font-weight: 600;
            color: var(--secondary-text-color);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }}

        .tab.active {{
            color: var(--tint-color);
            border-bottom: 2px solid var(--tint-color);
        }}

        /* Content switch */
        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        /* Compatibility Banner */
        .compat-banner {{
            background-color: var(--banner-bg);
            color: #ffffff;
            padding: 10px 14px;
            border-radius: 10px;
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}

        .section-title {{
            font-size: 17px;
            font-weight: 700;
            margin: 22px 0 10px 0;
            color: var(--text-color);
        }}

        .desc-text {{
            font-size: 15px;
            color: var(--text-color);
            line-height: 1.5;
            background-color: var(--card-color);
            padding: 14px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}

        /* 1:1 Banyungong 2-Column Grid Table */
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px 20px;
            background-color: var(--card-color);
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}

        .info-item {{
            display: flex;
            flex-direction: column;
        }}

        .info-label {{
            font-size: 13px;
            color: var(--secondary-text-color);
            margin-bottom: 5px;
        }}

        .info-value {{
            font-size: 15px;
            font-weight: 700;
            color: var(--text-color);
        }}

        /* Changelog Layout */
        .changelog-box {{
            background-color: var(--card-color);
            padding: 16px;
            border-radius: 12px;
            line-height: 1.6;
        }}
        .changelog-box h3, .changelog-box h4 {{
            margin-top: 0;
            color: var(--text-color);
        }}
        .changelog-box ul {{
            padding-left: 20px;
            margin: 0;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            color: var(--secondary-text-color);
            font-size: 12px;
            margin-top: 30px;
            padding: 20px 0;
            border-top: 1px solid var(--separator-color);
            line-height: 1.6;
        }}
    </style>
</head>
<body>

    <div class="top-banner">仉鹏的私人源</div>

    <div class="container">
        <!-- Package Header -->
        <div class="pkg-header">
            <img class="pkg-icon" src="{ctrl_dict.get('Icon', 'https://enix80126.github.io/jailbreak-repo/CydiaIcon.png')}" onerror="this.src='https://enix80126.github.io/jailbreak-repo/CydiaIcon.png';" alt="icon">
            <div class="pkg-header-info">
                <h1 class="pkg-name">{final_name_val}</h1>
                <p class="pkg-author">{ctrl_dict.get('Author', ctrl_dict.get('Maintainer', '未知'))}</p>
            </div>
            <button class="btn-get">获取</button>
        </div>

        <!-- Double Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="switchTab(event, 'intro-tab')">插件介绍</div>
            <div class="tab" onclick="switchTab(event, 'logs-tab')">更新日志</div>
        </div>

        <!-- Tab 1: Intro -->
        <div id="intro-tab" class="tab-content active">
            <!-- Dynamic Compatibility Banner -->
            <div id="compatibility-banner" class="compat-banner">
                <span id="compatibility-text">正在检测系统兼容性...</span>
            </div>

            <div class="section-title">插件介绍</div>
            <div class="desc-text">{pkg_desc}</div>

            <div class="section-title">版本详细说明</div>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">插件版本</span>
                    <span class="info-value">{pkg_version}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">插件更新时间</span>
                    <span class="info-value">{update_time}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">插件大小</span>
                    <span class="info-value">{size_str}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">插件系统兼容</span>
                    <span class="info-value">{fw_range}</span>
                </div>
            </div>
        </div>

        <!-- Tab 2: Changelog -->
        <div id="logs-tab" class="tab-content">
            <div class="section-title">更新历史说明</div>
            <div class="changelog-box">
                {changelog_text}
            </div>
        </div>

        <!-- Repository Footer -->
        <div class="footer">
            <strong>仉鹏的私人源</strong><br>
            本源由 GitHub Pages + jsDelivr 提供静态高速度分发支持。<br>
            © 2018 - 2026
        </div>
    </div>

    <script>
        // Tab switching logic
        function switchTab(event, tabId) {{
            const tabs = document.querySelectorAll('.tab');
            const contents = document.querySelectorAll('.tab-content');
            
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            event.currentTarget.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }}

        // Dynamic user-agent system compatibility checking
        (function checkCompatibility() {{
            const ua = navigator.userAgent;
            const minFw = parseFloat("{js_min_fw}");
            const maxFw = parseFloat("{js_max_fw}");
            
            let osVersion = null;
            const match = ua.match(/CPU (?:iPhone )?OS (\\d+)[_\\\\.](\\d+)(?:[_\\\\.](\\d+))? like Mac OS X/i);
            
            const banner = document.getElementById("compatibility-banner");
            const textSpan = document.getElementById("compatibility-text");
            
            if (match) {{
                osVersion = parseFloat(match[1] + "." + match[2]);
                const displayVersion = match[1] + "." + match[2] + (match[3] ? "." + match[3] : "");
                
                if (osVersion >= minFw && osVersion <= maxFw) {{
                    banner.style.backgroundColor = "var(--banner-bg)";
                    textSpan.innerHTML = "😊 您的系统: iOS " + displayVersion + " 👍 兼容该插件";
                }} else {{
                    banner.style.backgroundColor = "#ff3b30";
                    textSpan.innerHTML = "😢 您的系统: iOS " + displayVersion + " ⚠️ 可能不兼容";
                }}
            }} else {{
                // Fallback for desktop browser previews or other clients
                banner.style.backgroundColor = "var(--banner-bg)";
                textSpan.innerHTML = "😊 兼容 iOS " + "{js_min_fw}" + (parseFloat("{js_max_fw}") < 99.0 ? " ~ {js_max_fw}" : " 及以上系统");
            }}
        }})();
    </script>
</body>
</html>
"""

                dep_dir = os.path.join(repo, 'depictions')
                if not os.path.exists(dep_dir):
                    os.makedirs(dep_dir)

                dep_path = os.path.join(dep_dir, f"{pkg_id}.html")
                
                # Write HTML
                with open(dep_path, 'w', encoding='utf-8') as f_write:
                    f_write.write(html_content)

            import urllib.parse
            encoded_deb = urllib.parse.quote(deb)
            if pkg_id:
                out.append(f"Depiction: https://enix80126.github.io/jailbreak-repo/depictions/{pkg_id}.html")
            
            out += [f"Filename: https://cdn.jsdelivr.net/gh/enix80126/jailbreak-repo@main/debs/{encoded_deb}", f"Size: {size}",
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
