# chat_gui.py

import sys
from PyQt5 import QtWidgets, QtCore, QtGui
from chat_core import ChatCore

class ChatWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat")
        self.setGeometry(200, 200, 600, 500)
        self.setStyleSheet("background-color: #000000;")  # 设置黑色背景

        # 创建UI组件
        self.chat_display = QtWidgets.QListWidget()
        self.chat_display.setStyleSheet("background-color: #000000;")  # 黑色背景

        self.message_input = QtWidgets.QTextEdit()
        self.message_input.setStyleSheet("""
            background-color: #1e1e1e;
            color: #ff0000;
            font-size: 12pt;
        """)  # 深色背景，红色文字

        self.send_button = QtWidgets.QPushButton("发送")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #ff0000;
                font-weight: bold;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)  # 按钮样式

        self.export_button = QtWidgets.QPushButton("导出聊天记录")
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #ff0000;
                font-weight: bold;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)  # 按钮样式

        self.status_label = QtWidgets.QLabel("状态: 未连接")
        self.status_label.setStyleSheet("color: #ff0000;")  # 红色文字

        # 布局
        input_layout = QtWidgets.QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        bottom_layout = QtWidgets.QHBoxLayout()
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.export_button)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(self.chat_display)
        main_layout.addLayout(input_layout)
        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)

        # 连接信号和槽
        self.send_button.clicked.connect(self.send_message)
        self.message_input.installEventFilter(self)
        self.export_button.clicked.connect(self.export_chat)

        # 初始化核心模块
        self.chat_core = None
        self.chat_history = []

    def start_chat(self, mode, ip, port):
        # 创建核心模块实例
        self.chat_core = ChatCore(mode, ip, port)
        # 连接信号到槽函数
        self.chat_core.message_signal.connect(self.display_message)
        self.chat_core.status_signal.connect(self.update_status)

    def display_message(self, message_info):
        # 在聊天显示区域添加消息
        message = message_info['message']
        timestamp = message_info['timestamp']
        sender = message_info['sender']

        if sender == 'self':
            alignment = QtCore.Qt.AlignRight
            sender_name = "我"
            bg_color = "#333333"  # 深灰色背景
        else:
            alignment = QtCore.Qt.AlignLeft
            sender_name = "对方"
            bg_color = "#1e1e1e"  # 更深的灰色背景

        # 创建消息显示部件
        item_widget = QtWidgets.QWidget()
        item_layout = QtWidgets.QVBoxLayout()
        item_layout.setAlignment(alignment)

        message_label = QtWidgets.QLabel(message)
        message_label.setStyleSheet(f"""
            background-color: {bg_color};
            color: #ff0000;
            padding: 10px;
            border-radius: 10px;
            max-width: 300px;
        """)  # 消息样式

        time_label = QtWidgets.QLabel(f"{sender_name} [{timestamp}]")
        time_label.setStyleSheet("font-size: 8pt; color: #888888;")  # 时间戳样式

        item_layout.addWidget(message_label)
        item_layout.addWidget(time_label)
        item_widget.setLayout(item_layout)

        list_item = QtWidgets.QListWidgetItem()
        list_item.setSizeHint(item_widget.sizeHint())
        self.chat_display.addItem(list_item)
        self.chat_display.setItemWidget(list_item, item_widget)
        self.chat_display.scrollToBottom()

        # 保存聊天记录
        self.chat_history.append({
            'sender': sender_name,
            'timestamp': timestamp,
            'message': message
        })

    def update_status(self, status):
        # 更新状态标签
        self.status_label.setText(f"状态: {status}")

    def send_message(self):
        message_text = self.message_input.toPlainText().strip()
        if message_text:
            self.chat_core.send_message(message_text)
            self.message_input.clear()

    def eventFilter(self, obj, event):
        if obj == self.message_input:
            if event.type() == QtCore.QEvent.KeyPress:
                if event.key() == QtCore.Qt.Key_Return and not event.modifiers() & QtCore.Qt.ShiftModifier:
                    # 按下回车键且没有按住Shift，发送消息
                    self.send_message()
                    return True
                elif event.key() == QtCore.Qt.Key_Return and event.modifiers() & QtCore.Qt.ShiftModifier:
                    # 按下Shift+Enter，插入换行
                    cursor = self.message_input.textCursor()
                    cursor.insertText('\n')
                    return True
        return super().eventFilter(obj, event)

    def export_chat(self):
        # 导出聊天记录到文件
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "保存聊天记录", "", "Text Files (*.txt);;All Files (*)")
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    for entry in self.chat_history:
                        line = f"[{entry['timestamp']}] {entry['sender']}: {entry['message']}\n"
                        f.write(line)
                QtWidgets.QMessageBox.information(self, "导出成功", "聊天记录已成功导出。")
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "导出失败", f"聊天记录导出失败：{e}")

    def closeEvent(self, event):
        if self.chat_core:
            self.chat_core.close()
        event.accept()

def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('server', 'client'):
        print("Usage:")
        print("  python chat_gui.py server <bind_ip> <port>")
        print("  python chat_gui.py client <server_ip> <port>")
        return

    mode, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

    app = QtWidgets.QApplication(sys.argv)

    # 设置全局样式
    app.setStyle("Fusion")
    dark_palette = QtGui.QPalette()
    dark_palette.setColor(QtGui.QPalette.Window, QtGui.QColor(0, 0, 0))
    dark_palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.Base, QtGui.QColor(30, 30, 30))
    dark_palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(45, 45, 45))
    dark_palette.setColor(QtGui.QPalette.ToolTipBase, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.ToolTipText, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.Text, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.Button, QtGui.QColor(30, 30, 30))
    dark_palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.BrightText, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.Link, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(255, 0, 0))
    dark_palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor(0, 0, 0))
    app.setPalette(dark_palette)

    window = ChatWindow()
    window.show()
    window.start_chat(mode, ip, port)
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
