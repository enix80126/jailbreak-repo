#!/usr/bin/env python3
import os
import hashlib
import tarfile
import bz2
import io

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = os.path.getsize(filepath)
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            
    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def extract_control_from_deb(deb_path):
    """
    Extracts the 'control' file content from a .deb package (which is an ar archive).
    """
    with open(deb_path, 'rb') as f:
        # Verify ar signature
        sig = f.read(8)
        if sig != b"!<arch>\n":
            raise ValueError(f"Invalid deb file (bad signature): {deb_path}")
            
        while True:
            header = f.read(60)
            if len(header) < 60:
                break
                
            # Parse ar header
            file_name = header[0:16].decode('ascii').strip()
            file_size = int(header[48:58].decode('ascii').strip())
            
            # The data is always aligned to even byte boundaries
            data_size = file_size
            if data_size % 2 != 0:
                padded_size = data_size + 1
            else:
                padded_size = data_size
                
            if file_name.startswith('control.tar'):
                tar_data = f.read(data_size)
                
                # Determine compression
                compression = ''
                if file_name.endswith('.gz'):
                    compression = 'gz'
                elif file_name.endswith('.xz'):
                    compression = 'xz'
                elif file_name.endswith('.bz2'):
                    compression = 'bz2'
                
                # Open tar file from memory
                tar_bytes = io.BytesIO(tar_data)
                mode = f"r:{compression}" if compression else "r"
                
                with tarfile.open(fileobj=tar_bytes, mode=mode) as tar:
                    # Find control file
                    for member in tar.getmembers():
                        # The control file might be ./control or control
                        if member.name.endswith('control') and member.isfile():
                            control_file = tar.extractfile(member)
                            if control_file:
                                return control_file.read().decode('utf-8', errors='ignore')
                break
            else:
                # Skip this file's data
                f.seek(padded_size, os.SEEK_CUR)
                
    raise ValueError(f"Could not find control file in {deb_path}")

def generate_packages():
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    debs_dir = os.path.join(repo_dir, 'debs')
    packages_path = os.path.join(repo_dir, 'Packages')
    packages_bz2_path = os.path.join(repo_dir, 'Packages.bz2')
    
    if not os.path.exists(debs_dir):
        print(f"Error: {debs_dir} directory does not exist.")
        return

    packages_content = []
    
    # Scan all .deb files
    deb_files = [f for f in os.listdir(debs_dir) if f.endswith('.deb')]
    deb_files.sort()
    
    print(f"Found {len(deb_files)} .deb file(s) in debs/ directory.")
    
    for deb_file in deb_files:
        deb_path = os.path.join(debs_dir, deb_file)
        print(f"Processing {deb_file}...")
        
        try:
            # 1. Extract control metadata
            control_text = extract_control_from_deb(deb_path)
            
            # 2. Get file properties
            size, md5, sha1, sha256 = get_hashes(deb_path)
            
            # 3. Format control block
            control_lines = control_text.strip().split('\n')
            cleaned_lines = []
            for line in control_lines:
                # Remove any existing location/checksum lines to avoid duplication
                lower_line = line.lower()
                if any(lower_line.startswith(field) for field in ['filename:', 'size:', 'md5sum:', 'sha1:', 'sha256:']):
                    continue
                cleaned_lines.append(line)
                
            # Add package location and hash fields
            cleaned_lines.append(f"Filename: debs/{deb_file}")
            cleaned_lines.append(f"Size: {size}")
            cleaned_lines.append(f"MD5sum: {md5}")
            cleaned_lines.append(f"SHA1: {sha1}")
            cleaned_lines.append(f"SHA256: {sha256}")
            
            packages_content.append('\n'.join(cleaned_lines))
            
        except Exception as e:
            print(f"Error processing {deb_file}: {e}")
            
    # Write Packages
    packages_data = '\n\n'.join(packages_content) + '\n'
    with open(packages_path, 'w', encoding='utf-8') as f:
        f.write(packages_data)
    print(f"Successfully generated {packages_path}")
    
    # Write Packages.bz2
    with bz2.open(packages_bz2_path, 'wb') as f:
        f.write(packages_data.encode('utf-8'))
    print(f"Successfully generated {packages_bz2_path}")

if __name__ == '__main__':
    generate_packages()
