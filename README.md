# 我的越狱源 (My Jailbreak Repo)

这是一个基于 GitHub Pages 托管的个人越狱源。你可以在越狱设备的包管理器（Cydia, Sileo, Zebra等）中直接添加本源。

## 📲 添加源地址

在包管理器中添加以下地址：

```
https://<您的GitHub用户名>.github.io/jailbreak-repo/
```

> ⚠️ **注意**：在正式发布前，请将上方链接中的 `<您的GitHub用户名>` 替换为您的 GitHub 实际账号名称。

---

## 🛠️ 如何维护和更新此源（给源作者的指南）

当您有新的 `.deb` 插件包需要发布或更新时，请按照以下步骤操作：

### 第一步：放入新的 deb 包
将打包好的 `.deb` 文件放入 `debs/` 文件夹中。

### 第二步：更新源的索引文件
在本地仓库根目录下运行自动化扫描脚本：

```bash
python scan.py
```

该脚本将自动扫描 `debs/` 目录下的所有文件，读取包信息，并自动重新生成 `Packages` 和 `Packages.bz2`。

### 第三步：推送至 GitHub
更新完成后，将修改提交并推送到 GitHub 仓库：

```bash
git add .
git commit -m "Update packages"
git push origin main
```

推送成功后，GitHub Pages 会在几分钟内自动构建完成，您的包管理器即可刷新并获取到最新版本的插件。

---

## 📁 目录结构说明

*   `debs/` - 存放所有的越狱包文件 (`.deb`)。
*   `CydiaIcon.png` - 该源在 Cydia 等包管理器中显示的图标。
*   `Release` - 该源的基本信息元数据（源名称、描述等）。
*   `Packages` & `Packages.bz2` - 包列表索引文件（由 `scan.py` 自动生成）。
*   `scan.py` - 本地自动生成索引文件的跨平台 Python 脚本。
