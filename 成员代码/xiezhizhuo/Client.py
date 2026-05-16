import socket
import sys
import os
import time

"""
安全风险注释：
1. 文件名校验仅简单拦截..，路径穿越漏洞防护不全
2. 客户端与服务端明文传输数据，存在窃听风险
3. 未校验接收文件内容，存在写入恶意文件隐患
"""

# 常量定义 【修改：规范常量命名，消除魔法数字】
DEFAULT_SERVER_PORT = 34000        # 预设服务端通信端口
DEFAULT_SERVER_IP = "127.0.0.1"    # 默认本地服务地址
BUFFER_SIZE_1M = 1048576           # 定义1MB数据接收缓冲区大小
CLIENT_EXIT_CHAR = "+++"           # 定义客户端退出指令标识


# 工具函数
def print_welcome():
    """打印欢迎信息"""
    print("=" * 50)
    print(" Simple TCP File Client ")
    print("=" * 50)
    print(f"Server Address: {DEFAULT_SERVER_IP}:{DEFAULT_SERVER_PORT}")
    print(f"Enter '{CLIENT_EXIT_CHAR}' to exit")
    print("=" * 50)


def validate_filename(filename):
    """检查文件名是否合法"""
    if not filename:
        print("Error: filename is empty")
        return False

    # 防止路径穿越
    if ".." in filename or filename.startswith("/"):
        print("Error: invalid filename")
        return False

    return True


def create_file(filename):
    """创建文件用于写入"""
    try:
        fp = open(filename, "wb")
        print(f"[INFO] File '{filename}' opened successfully")
        return fp
    except Exception as e:
        print(f"[ERROR] Cannot open file '{filename}': {str(e)}")
        return None


def receive_file(sockfd, fp):
    """接收文件内容"""
    total_bytes = 0
    start_time = time.time()

    while True:
        try:
            # 【修改：使用命名常量替代原始数字】
            data = sockfd.recv(BUFFER_SIZE_1M)
        except socket.timeout:
            print("[WARNING] Receive timeout")
            break

        if not data:
            break

        fp.write(data)
        total_bytes += len(data)

    end_time = time.time()
    duration = end_time - start_time

    return total_bytes, duration


def print_stats(filename, total_bytes, duration):
    """打印接收统计信息"""
    print("\n[RESULT]")
    print(f"File Name     : {filename}")
    print(f"Bytes Received: {total_bytes}")

    if duration > 0:
        speed = total_bytes / duration / 1024  # KB/s
        print(f"Time Used     : {duration:.2f} s")
        print(f"Speed         : {speed:.2f} KB/s")

    print("=" * 50)


def connect_server():
    """创建并连接socket"""
    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[DEBUG] Socket FD: {sockfd.fileno()}")
        # 【修改：使用规范命名常量连接服务端】
        sockfd.connect((DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT))
        print(f"[INFO] Connected to server {DEFAULT_SERVER_IP}:{DEFAULT_SERVER_PORT}")

        return sockfd

    except ConnectionRefusedError:
        print("[ERROR] Connection refused. Server may be down.")
    except socket.gaierror:
        print("[ERROR] Invalid IP address")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")

    return None


# 主逻辑
def main():
    print_welcome()

    sockfd = connect_server()
    if not sockfd:
        return

    try:
        while True:
            filename = input("\nPlease enter the required document: ").strip()

            # 【修改：使用定义好的退出标识常量】
            if filename == CLIENT_EXIT_CHAR:
                print("[INFO] Exit command received")
                break

            # 文件名校验
            if not validate_filename(filename):
                continue

            # 发送文件名
            try:
                sockfd.sendall(filename.encode())
                print(f"[INFO] Sent filename: {filename}")
            except Exception as e:
                print(f"[ERROR] Failed to send filename: {str(e)}")
                break

            # 创建文件
            fp = create_file(filename)
            if fp is None:
                continue

            # 接收文件
            total_bytes, duration = receive_file(sockfd, fp)

            # 关闭文件
            fp.close()

            # 判断服务器状态
            if total_bytes == 0:
                print("[WARNING] Server may have disconnected")
                break

            # 输出统计信息
            print_stats(filename, total_bytes, duration)

    finally:
        print("[INFO] Closing connection...")
        sockfd.close()
        print("[INFO] Client exited successfully")


# 程序入口
if __name__ == "__main__":
    main()
