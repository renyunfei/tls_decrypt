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
        seq_client = 1000
        seq_server = 2000
        
        # TCP三次握手 (Three-way handshake)
        # 1. SYN from client
        tcp_syn = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=0,
            flags=dpkt.tcp.TH_SYN,
            win=65535,
            data=b''
        )
        
        ip_syn = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_syn
        )
        
        eth_syn = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_syn
        )
        
        pcap_writer.writepkt(eth_syn, ts=timestamp)
        print(f"  ✓ 添加了TCP SYN包 (三次握手 1/3)")
        
        # 2. SYN-ACK from server
        tcp_synack = dpkt.tcp.TCP(
            sport=dst_port,
            dport=src_port,
            seq=seq_server,
            ack=seq_client + 1,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_synack = dpkt.ip.IP(
            src=dst_ip,
            dst=src_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_synack
        )
        
        eth_synack = dpkt.ethernet.Ethernet(
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            src=b'\x00\x11\x22\x33\x44\x55',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_synack
        )
        
        pcap_writer.writepkt(eth_synack, ts=timestamp + 0.01)
        print(f"  ✓ 添加了TCP SYN-ACK包 (三次握手 2/3)")
        
        # 3. ACK from client
        seq_client += 1
        seq_server += 1
        
        tcp_ack = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=seq_server,
            flags=dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_ack = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_ack
        )
        
        eth_ack = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_ack
        )
        
        pcap_writer.writepkt(eth_ack, ts=timestamp + 0.02)
        print(f"  ✓ 添加了TCP ACK包 (三次握手 3/3)")
        
        # 1. 创建Client Hello包
        client_hello = create_tls_client_hello()
        
        tcp_client = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=seq_server,
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
        
        pcap_writer.writepkt(eth_client, ts=timestamp + 0.03)
        print(f"  ✓ 添加了Client Hello包")
        seq_client += len(client_hello)
        
        # 2. 创建Server Hello包
        server_hello = create_tls_server_hello()
        
        tcp_server = dpkt.tcp.TCP(
            sport=dst_port,
            dport=src_port,
            seq=seq_server,
            ack=seq_client,
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
        
        pcap_writer.writepkt(eth_server, ts=timestamp + 0.04)
        print(f"  ✓ 添加了Server Hello包")
        seq_server += len(server_hello)
        
        # 3. 创建加密应用数据包
        app_data = create_tls_application_data()
        
        tcp_app = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=seq_server,
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
        
        pcap_writer.writepkt(eth_app, ts=timestamp + 0.05)
        print(f"  ✓ 添加了加密应用数据包")
        seq_client += len(app_data)
        
        # TCP四次挥手 (Four-way teardown)
        # 1. FIN-ACK from client
        tcp_fin1 = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=seq_server,
            flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_fin1 = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_fin1
        )
        
        eth_fin1 = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_fin1
        )
        
        pcap_writer.writepkt(eth_fin1, ts=timestamp + 0.06)
        print(f"  ✓ 添加了TCP FIN-ACK包 (四次挥手 1/4)")
        seq_client += 1
        
        # 2. ACK from server
        tcp_ack2 = dpkt.tcp.TCP(
            sport=dst_port,
            dport=src_port,
            seq=seq_server,
            ack=seq_client,
            flags=dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_ack2 = dpkt.ip.IP(
            src=dst_ip,
            dst=src_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_ack2
        )
        
        eth_ack2 = dpkt.ethernet.Ethernet(
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            src=b'\x00\x11\x22\x33\x44\x55',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_ack2
        )
        
        pcap_writer.writepkt(eth_ack2, ts=timestamp + 0.07)
        print(f"  ✓ 添加了TCP ACK包 (四次挥手 2/4)")
        
        # 3. FIN-ACK from server
        tcp_fin2 = dpkt.tcp.TCP(
            sport=dst_port,
            dport=src_port,
            seq=seq_server,
            ack=seq_client,
            flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_fin2 = dpkt.ip.IP(
            src=dst_ip,
            dst=src_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_fin2
        )
        
        eth_fin2 = dpkt.ethernet.Ethernet(
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            src=b'\x00\x11\x22\x33\x44\x55',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_fin2
        )
        
        pcap_writer.writepkt(eth_fin2, ts=timestamp + 0.08)
        print(f"  ✓ 添加了TCP FIN-ACK包 (四次挥手 3/4)")
        seq_server += 1
        
        # 4. ACK from client
        tcp_ack3 = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_client,
            ack=seq_server,
            flags=dpkt.tcp.TH_ACK,
            win=65535,
            data=b''
        )
        
        ip_ack3 = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_ack3
        )
        
        eth_ack3 = dpkt.ethernet.Ethernet(
            dst=b'\x00\x11\x22\x33\x44\x55',
            src=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_ack3
        )
        
        pcap_writer.writepkt(eth_ack3, ts=timestamp + 0.09)
        print(f"  ✓ 添加了TCP ACK包 (四次挥手 4/4)")
    
    print(f"\n示例PCAP文件创建成功: {filename}")
    print(f"包含:")
    print(f"  - TCP三次握手 (3个包)")
    print(f"  - 1个Client Hello (带Random)")
    print(f"  - 1个Server Hello (带Random)")
    print(f"  - 1个加密应用数据")
    print(f"  - TCP四次挥手 (4个包)")


if __name__ == "__main__":
    create_sample_pcap()
