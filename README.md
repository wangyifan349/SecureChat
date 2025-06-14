# 🔐 加密聊天应用程序

欢迎使用**加密聊天应用程序**！这个项目使用 Python 构建，实现了一个安全的聊天系统，确保您的通信内容安全可靠。

## 💡 功能亮点

- **🔑 安全通信**：使用 X25519 算法进行密钥交换，通过 AES-GCM 模式进行对称加密，加密算法确保数据的机密性和完整性。
- **🔄 多线程处理**：采用多线程模型，分别处理消息的发送和接收，保障实时通信效果。
- **🔄 自动重连**：在失去连接后应用会自动尝试重连，保证通信的稳定性。

## 🛠 安装指南

请按照以下步骤安装和运行该应用程序：

1. 克隆此仓库：

    ```bash
    git clone https://github.com/wangyifan349/SecureChat.git
    cd SecureChat
    ```

2. 安装 Python 依赖项：

    ```bash
    pip install cryptography
    ```

## 🚀 使用方法

### 启动服务器

1. 运行服务器 Python 脚本：

    ```bash
    python server.py
    ```

2. 服务器会在 65432 端口监听客户端连接请求，一旦连接建立，即可进行加密通信。

### 启动客户端

1. 在另一终端窗口中运行客户端脚本：

    ```bash
    python client.py
    ```

2. 客户端会连接到服务器，建立起加密的通信通道。

3. 在服务器或客户端终端中输入消息内容并发送，输入 `exit` 可关闭连接。

## 📜 许可证

本项目基于 MIT 许可证授权，详情请参阅 [LICENSE](LICENSE) 文件。


赞助我  
  USDT  0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b

BNB Smart Chain 0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
  
---

感谢你对开源社区的贡献！如果您有任何疑问或建议，请随时提交 issue 或 pull request。😊
