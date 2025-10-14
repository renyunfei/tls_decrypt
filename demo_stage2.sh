#!/bin/bash
# Stage 2 功能演示脚本
# Demonstration script for Stage 2 functionality

echo "=========================================="
echo "TLS Decrypt - Stage 2 演示"
echo "PCAP转存功能 - SHA256哈希"
echo "=========================================="
echo

# 检查示例文件
if [ ! -f "sample_tls.pcap" ]; then
    echo "创建示例PCAP文件..."
    python3 create_sample_pcap.py
    echo
fi

echo "步骤 1: 查看原始PCAP文件内容"
echo "----------------------------------------"
echo "命令: python3 tls_parser.py sample_tls.pcap"
echo
python3 tls_parser.py sample_tls.pcap
echo

echo "步骤 2: 转存PCAP文件（SHA256哈希）"
echo "----------------------------------------"
echo "命令: python3 tls_parser.py sample_tls.pcap demo_output.pcap"
echo
python3 tls_parser.py sample_tls.pcap demo_output.pcap
echo

echo "步骤 3: 验证输出文件"
echo "----------------------------------------"
python3 << 'PYEOF'
import dpkt

print("读取输出文件: demo_output.pcap\n")

with open('demo_output.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    
    for i, (timestamp, buf) in enumerate(pcap, 1):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        print(f'数据包 #{i}:')
        print(f'  源地址: {dpkt.utils.inet_to_str(ip.src)}:{tcp.sport}')
        print(f'  目标地址: {dpkt.utils.inet_to_str(ip.dst)}:{tcp.dport}')
        print(f'  时间戳: {timestamp}')
        print(f'  TCP载荷长度: {len(tcp.data)} bytes')
        print(f'  TCP载荷(SHA256): {tcp.data.hex()}')
        print()
PYEOF

# 清理临时文件
rm -f demo_output.pcap

echo "=========================================="
echo "演示完成！"
echo "=========================================="
