# Workspace Rules & Context: Jailbreak Repository

This project is a self-hosted iOS Cydia/Sileo jailbreak package repository. It uses a hybrid hosting architecture combining GitHub Pages (for real-time index files) and jsDelivr CDN (for high-speed `.deb` downloads).

## 1. Repository Structure
*   `debs/`: Directory containing the `.deb` package files.
*   `Packages` & `Packages.bz2`: Index files listing package metadata, parsed from the `.deb` files.
*   `Release`: Metadata file declaring repository properties (Label, Origin, Suite, Architectures).
*   `scan.py`: Python script to scan `.deb` files and generate/update the indices.
*   `.github/workflows/scan.yml`: GitHub Actions runner that automatically triggers `scan.py` on Linux when `.deb` files are pushed.

## 2. Compilation & Formatting Rules
To ensure Sileo and APT can parse the index files properly:
*   **Enforce Unix LF Line Endings**: Sileo/APT will fail with `Unable to locate package` errors if index files (`Packages`, `Release`) use Windows CRLF line endings. The `core.autocrlf` setting in git should remain `false`.
*   **Absolute CDN Download URLs**: In the `Packages` file, the `Filename` field must be formatted as an absolute jsDelivr CDN URL:
    `Filename: https://cdn.jsdelivr.net/gh/enix80126/jailbreak-repo@main/debs/<URL_ENCODED_FILENAME>`
*   **Filename URL Encoding**: Filenames written to the `Packages` index must be URL-encoded (using `urllib.parse.quote`) to prevent spaces or special characters from breaking Sileo's parser.
*   **Zstandard (.zst) Support**: Many modern `.deb` files use `.zst` compression. The `scan.py` script depends on the `zstandard` Python module to extract package metadata. When running in a new environment, make sure to run `pip install zstandard` first.

## 3. Auto-Renaming Conventions
When `scan.py` runs, it automatically standardizes package names based on their target architecture:
*   **`iphoneos-arm64e` (RootHide)**: Any existing `rootless`/`rootful` tag suffixes in the package `Name` field are stripped, and a unified ` (RootHide)` suffix is appended.
*   **`iphoneos-arm64` (Rootless)**: Any existing `roothide`/`rootful` tag suffixes are stripped, and a unified ` (Rootless)` suffix is appended.
*   **`iphoneos-arm` (Rootful)**: Any existing `rootless`/`roothide` tag suffixes are stripped, and a unified ` (Rootful)` suffix is appended.
*   *Note*: The renaming regex uses `$` (end-of-string anchor) to avoid breaking proper nouns like `rootless-compat`.

## 4. Hosting & CDN Links
*   **Sileo Source URL**: `https://enix80126.github.io/jailbreak-repo/` (served live via GitHub Pages to bypass CDN caching delays for index files).
*   **CDN File Delivery**: Managed automatically by referencing `cdn.jsdelivr.net` directly inside the `Packages` index for high-speed file distribution.
