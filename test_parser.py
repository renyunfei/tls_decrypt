#!/usr/bin/env python3
"""
测试TLS解析器的功能
Test TLS parser functionality
"""

import subprocess
import os


def test_requirements():
    """测试三个主要需求"""
    print("=" * 80)
    print("测试TLS解析器 - 验证三个阶段任务")
    print("Testing TLS Parser - Verifying Stage Requirements")
    print("=" * 80)
    print()
    
    # 确保示例文件存在
    if not os.path.exists('sample_tls.pcap'):
        print("创建示例PCAP文件...")
        subprocess.run(['python3', 'create_sample_pcap.py'])
        print()
    
    print("运行TLS解析器...")
    print("-" * 80)
    result = subprocess.run(
        ['python3', 'tls_parser.py', 'sample_tls.pcap'],
        capture_output=True,
        text=True
    )
    
    output = result.stdout
    print(output)
    
    print()
    print("=" * 80)
    print("验证结果 (Verification Results)")
    print("=" * 80)
    
    # 验证任务1: 识别并解析TLS会话
    task1_passed = "TLS会话" in output and "数据包" in output
    print(f"✓ 任务1: 使用dpkt识别并解析TLS会话 - {'通过' if task1_passed else '失败'}")
    print(f"  Found TLS sessions: {output.count('TLS会话')} sessions")
    
    # 验证任务2: 识别并解析random
    task2_passed = "Random值" in output and "ClientHello" in output and "ServerHello" in output
    print(f"✓ 任务2: 识别并解析Random值 - {'通过' if task2_passed else '失败'}")
    print(f"  Found Random values in: ClientHello and ServerHello")
    
    # 验证任务3: 识别并解析加密载荷，十六进制打印
    task3_passed = "加密载荷" in output and "十六进制" in output and "ApplicationData" in output
    print(f"✓ 任务3: 识别并解析加密载荷(十六进制) - {'通过' if task3_passed else '失败'}")
    print(f"  Found encrypted payload in Application Data")
    
    print()
    if task1_passed and task2_passed and task3_passed:
        print("🎉 所有任务完成! (All tasks completed!)")
        return True
    else:
        print("❌ 部分任务未完成 (Some tasks failed)")
        return False


if __name__ == "__main__":
    success = test_requirements()
    exit(0 if success else 1)
