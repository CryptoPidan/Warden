---

# Warden 自动化脚本

本项目是基于 **.NET 9** 和 **C# 13.0** 开发的 Warden Protocol 自动化工具，支持多账号、多代理、每日任务自动执行等功能，旨在提升交互效率并实现自动化操作。

---

## ✨ 功能特性

* ✅ 支持多账号批量操作
* 🌐 支持 HTTP/HTTPS 多类型代理（支持带用户名密码认证）
* 🔁 自动完成每日任务（登录、AI 对话、小游戏等）
* 🧩 支持推荐码设置及自动生成 Token（用于邀请小号，默认关闭）
* ♻️ 任务自动循环执行，失败自动重试
* 📄 日志输出到控制台及本地文件（`Log.txt`）
* 🔄 Swap 功能（存在损耗，未发开）

---

## 📦 文件结构

* `PrivateKey.txt`：每行一以太坊私钥
* `Proxy.txt`：每行一个代理，支持以下格式（不支持SOCKS)：

```txt
ip:port
http://ip:port
https://ip:port
http://username:password@ip:port
https://username:password@ip:port
```

* `Log.txt`：运行日志自动写入本文件

---

## 🛠️ 开发环境

* Visual Studio 2022 (C#)
* .NET SDK 9.0+

---

## 🖥️ 系统支持

* Windows 10 / 11
* Linux
* macOS

---

## 📚 安装依赖

请确保安装以下 NuGet 包（可通过 NuGet 包管理器或 CLI 安装）：

* `Nethereum.Signer`
* `Newtonsoft.Json`

---

## 🚀 快速开始

1. 准备账号与代理：

   * 编辑 `PrivateKey.txt` 添加钱包私钥（每行一个）
   * （可选）编辑 `Proxy.txt` 添加代理（支持多种格式）

2. 编译并运行项目或于Release下载使用：

   * 在 Visual Studio 中打开项目，点击运行，或通过命令行编译执行

3. 程序会自动循环执行任务，并输出运行日志

---

## 📝 日志说明

* 控制台实时输出当前执行状态
* 所有执行日志记录于根目录下的 `Log.txt` 文件中

---

## ⚠️ 注意事项

* 请妥善保管私钥，**避免泄露或上传到公共仓库**
* 本工具仅供学习和研究用途，**严禁用于任何非法行为**
* 如遇 API 接口变更或异常，可通过日志定位问题进行排查

---

## 🤝 贡献指南

欢迎提交 Issues 或 Pull Requests

---