#!/usr/bin/env python3
"""
测试PCAP转存功能
Test PCAP save functionality with SHA256 hashing
"""

import subprocess
import os
import dpkt
import hashlib


def test_save_pcap():
    """测试PCAP转存功能的三个核心要求"""
    print("=" * 80)
    print("测试PCAP转存功能 - SHA256哈希")
    print("Testing PCAP Save Functionality - SHA256 Hashing")
    print("=" * 80)
    print()
    
    # 确保示例文件存在
    if not os.path.exists('sample_tls.pcap'):
        print("创建示例PCAP文件...")
        subprocess.run(['python3', 'create_sample_pcap.py'])
        print()
    
    # 运行转存功能
    output_file = 'test_output.pcap'
    print(f"运行转存功能: sample_tls.pcap -> {output_file}")
    print("-" * 80)
    result = subprocess.run(
        ['python3', 'tls_parser.py', 'sample_tls.pcap', output_file],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"错误: {result.stderr}")
        return False
    
    print()
    print("=" * 80)
    print("验证结果 (Verification Results)")
    print("=" * 80)
    print()
    
    # 读取原始和输出PCAP文件进行验证
    original_packets = []
    with open('sample_tls.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            if len(tcp.data) == 0 or tcp.data[0] != 23:
                continue
            
            # 提取加密载荷
            length = int.from_bytes(tcp.data[3:5], byteorder='big')
            fragment = tcp.data[5:5+length]
            
            original_packets.append({
                'timestamp': timestamp,
                'src_ip': dpkt.utils.inet_to_str(ip.src),
                'dst_ip': dpkt.utils.inet_to_str(ip.dst),
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'payload': fragment,
                'sha256': hashlib.sha256(fragment).digest()
            })
    
    output_packets = []
    with open(output_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            
            output_packets.append({
                'timestamp': timestamp,
                'src_ip': dpkt.utils.inet_to_str(ip.src),
                'dst_ip': dpkt.utils.inet_to_str(ip.dst),
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'payload': tcp.data
            })
    
    # 验证三个核心要求
    print("要求1: 通信双方的IP和端口不变")
    all_match = True
    for i, (orig, out) in enumerate(zip(original_packets, output_packets), 1):
        ip_port_match = (
            orig['src_ip'] == out['src_ip'] and
            orig['dst_ip'] == out['dst_ip'] and
            orig['src_port'] == out['src_port'] and
            orig['dst_port'] == out['dst_port']
        )
        
        if ip_port_match:
            print(f"  ✓ 数据包 #{i}: {orig['src_ip']}:{orig['src_port']} -> {orig['dst_ip']}:{orig['dst_port']} (匹配)")
        else:
            print(f"  ✗ 数据包 #{i}: IP/端口不匹配")
            all_match = False
    
    if all_match:
        print("  结果: 通过 ✓\n")
    else:
        print("  结果: 失败 ✗\n")
    
    print("要求2: 每个TCP包的PCAP的时间戳不变")
    timestamp_match = True
    for i, (orig, out) in enumerate(zip(original_packets, output_packets), 1):
        if abs(orig['timestamp'] - out['timestamp']) < 0.0001:  # 允许浮点误差
            print(f"  ✓ 数据包 #{i}: 时间戳 {orig['timestamp']} (匹配)")
        else:
            print(f"  ✗ 数据包 #{i}: 时间戳不匹配 (原始: {orig['timestamp']}, 输出: {out['timestamp']})")
            timestamp_match = False
    
    if timestamp_match:
        print("  结果: 通过 ✓\n")
    else:
        print("  结果: 失败 ✗\n")
    
    print("要求3: TCP载荷为原始加密载荷的SHA256哈希值")
    sha256_match = True
    for i, (orig, out) in enumerate(zip(original_packets, output_packets), 1):
        if orig['sha256'] == out['payload']:
            print(f"  ✓ 数据包 #{i}: SHA256匹配")
            print(f"    原始载荷长度: {len(orig['payload'])} bytes")
            print(f"    SHA256哈希: {orig['sha256'].hex()}")
        else:
            print(f"  ✗ 数据包 #{i}: SHA256不匹配")
            sha256_match = False
    
    if sha256_match:
        print("  结果: 通过 ✓\n")
    else:
        print("  结果: 失败 ✗\n")
    
    print("=" * 80)
    if all_match and timestamp_match and sha256_match:
        print("🎉 所有测试通过! (All tests passed!)")
        print("=" * 80)
        
        # 清理测试文件
        if os.path.exists(output_file):
            os.remove(output_file)
        
        return True
    else:
        print("❌ 部分测试失败 (Some tests failed)")
        print("=" * 80)
        return False


if __name__ == "__main__":
    success = test_save_pcap()
    exit(0 if success else 1)
