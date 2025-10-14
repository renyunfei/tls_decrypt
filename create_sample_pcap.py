#!/usr/bin/env python3
"""
创建一个示例PCAP文件，包含TLS握手和加密数据
Create a sample PCAP file with TLS handshake and encrypted data
"""

import dpkt
import socket
import struct
import time


def create_tls_client_hello():
    """创建一个TLS Client Hello消息"""
    # TLS版本 (TLS 1.2 = 0x0303)
    tls_version = b'\x03\x03'
    
    # Random (32 bytes): 4字节时间戳 + 28字节随机数
    import os
    random = struct.pack('!I', int(time.time())) + os.urandom(28)
    
    # Session ID Length (1 byte) + Session ID (0 bytes for simplicity)
    session_id = b'\x00'
    
    # Cipher Suites Length (2 bytes) + Cipher Suites (2 bytes each)
    # 例如: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    cipher_suites = b'\x00\x02\x00\x2f'
    
    # Compression Methods Length (1 byte) + Compression Methods (1 byte)
    compression = b'\x01\x00'
    
    # 构建Client Hello消息体
    client_hello_body = tls_version + random + session_id + cipher_suites + compression
    
    # Handshake消息头: Type (1 byte) + Length (3 bytes)
    handshake_type = b'\x01'  # Client Hello
    handshake_length = struct.pack('!I', len(client_hello_body))[1:]  # 取后3字节
    
    handshake_msg = handshake_type + handshake_length + client_hello_body
    
    # TLS记录层: Content Type (1 byte) + Version (2 bytes) + Length (2 bytes) + Fragment
    content_type = b'\x16'  # Handshake
    record_version = b'\x03\x03'  # TLS 1.2
    record_length = struct.pack('!H', len(handshake_msg))
    
    tls_record = content_type + record_version + record_length + handshake_msg
    
    return tls_record


def create_tls_server_hello():
    """创建一个TLS Server Hello消息"""
    # TLS版本 (TLS 1.2 = 0x0303)
    tls_version = b'\x03\x03'
    
    # Random (32 bytes): 4字节时间戳 + 28字节随机数
    import os
    random = struct.pack('!I', int(time.time()) + 1) + os.urandom(28)
    
    # Session ID Length (1 byte) + Session ID
    session_id = b'\x20' + os.urandom(32)  # 32字节会话ID
    
    # Cipher Suite (2 bytes)
    cipher_suite = b'\x00\x2f'
    
    # Compression Method (1 byte)
    compression = b'\x00'
    
    # 构建Server Hello消息体
    server_hello_body = tls_version + random + session_id + cipher_suite + compression
    
    # Handshake消息头: Type (1 byte) + Length (3 bytes)
    handshake_type = b'\x02'  # Server Hello
    handshake_length = struct.pack('!I', len(server_hello_body))[1:]  # 取后3字节
    
    handshake_msg = handshake_type + handshake_length + server_hello_body
    
    # TLS记录层
    content_type = b'\x16'  # Handshake
    record_version = b'\x03\x03'  # TLS 1.2
    record_length = struct.pack('!H', len(handshake_msg))
    
    tls_record = content_type + record_version + record_length + handshake_msg
    
    return tls_record


def create_tls_application_data():
    """创建一个TLS加密应用数据消息"""
    import os
    # 模拟加密数据 (64字节)
    encrypted_data = os.urandom(64)
    
    # TLS记录层
    content_type = b'\x17'  # Application Data
    record_version = b'\x03\x03'  # TLS 1.2
    record_length = struct.pack('!H', len(encrypted_data))
    
    tls_record = content_type + record_version + record_length + encrypted_data
    
    return tls_record


def create_sample_pcap(filename='sample_tls.pcap'):
    """创建示例PCAP文件"""
    print(f"正在创建示例PCAP文件: {filename}")
    
    # 创建PCAP写入器
    with open(filename, 'wb') as f:
        pcap_writer = dpkt.pcap.Writer(f)
        
        # 模拟源和目标IP地址
        src_ip = socket.inet_aton('192.168.1.100')
        dst_ip = socket.inet_aton('93.184.216.34')  # example.com
        src_port = 54321
        dst_port = 443
        
        timestamp = time.time()
        
        # 1. 创建Client Hello包
        client_hello = create_tls_client_hello()
        
        tcp_client = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=1000,
            ack=0,
            flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
            data=client_hello
        )
        
        ip_client = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_client
        )
        
        eth_client = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_client
        )
        
        pcap_writer.writepkt(eth_client, ts=timestamp)
        print(f"  ✓ 添加了Client Hello包")
        
        # 2. 创建Server Hello包
        server_hello = create_tls_server_hello()
        
        tcp_server = dpkt.tcp.TCP(
            sport=dst_port,
            dport=src_port,
            seq=2000,
            ack=1000 + len(client_hello),
            flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
            data=server_hello
        )
        
        ip_server = dpkt.ip.IP(
            src=dst_ip,
            dst=src_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_server
        )
        
        eth_server = dpkt.ethernet.Ethernet(
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            src=b'\x00\x11\x22\x33\x44\x55',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_server
        )
        
        pcap_writer.writepkt(eth_server, ts=timestamp + 0.1)
        print(f"  ✓ 添加了Server Hello包")
        
        # 3. 创建加密应用数据包
        app_data = create_tls_application_data()
        
        tcp_app = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=1000 + len(client_hello),
            ack=2000 + len(server_hello),
            flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
            data=app_data
        )
        
        ip_app = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_app
        )
        
        eth_app = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_app
        )
        
        pcap_writer.writepkt(eth_app, ts=timestamp + 0.2)
        print(f"  ✓ 添加了加密应用数据包")
    
    print(f"\n示例PCAP文件创建成功: {filename}")
    print(f"包含:")
    print(f"  - 1个Client Hello (带Random)")
    print(f"  - 1个Server Hello (带Random)")
    print(f"  - 1个加密应用数据")


if __name__ == "__main__":
    create_sample_pcap()
