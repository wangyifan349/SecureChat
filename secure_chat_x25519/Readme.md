# Secure Chat Application

这是一个使用Python编写的安全聊天应用程序，支持终端版本和GUI界面版本。该应用程序使用X25519密钥交换和ChaCha20-Poly1305对称加密算法，确保通信的安全性和私密性。

## 功能特性

- **安全通信**：使用X25519密钥交换和ChaCha20-Poly1305加密，保障消息传输的安全性。
- **美观的GUI界面**：使用PyQt5构建，支持护眼模式（黑色背景，红色文字）。
- **消息展示**：
  - 自己发送的消息显示在右侧，对方的消息显示在左侧。
  - 支持消息气泡样式，附带时间戳。
  - 支持发送多行消息（Shift+Enter换行）。
- **导出聊天记录**：可将聊天记录导出为文本文件，方便保存和查看。

## 依赖库

请确保安装以下Python库：

- [PyNaCl](https://pypi.org/project/PyNaCl/)
- [PyCryptodome](https://pypi.org/project/pycryptodome/)
- [PyQt5](https://pypi.org/project/PyQt5/)

安装命令：

```bash
pip install pynacl pycryptodome pyqt5
