#!/bin/bash
echo "======================================================================"
echo "TLS解析器演示 (TLS Parser Demo)"
echo "======================================================================"
echo ""
echo "1. 检查依赖 (Checking dependencies)..."
pip3 show dpkt | grep "Name:\|Version:" || echo "请运行: pip install -r requirements.txt"
echo ""
echo "2. 创建示例PCAP文件 (Creating sample PCAP)..."
python3 create_sample_pcap.py
echo ""
echo "3. 运行TLS解析器 (Running TLS parser)..."
python3 tls_parser.py sample_tls.pcap
echo ""
echo "4. 运行测试验证 (Running tests)..."
python3 test_parser.py
echo ""
echo "======================================================================"
echo "演示完成! (Demo completed!)"
echo "======================================================================"
