#!/usr/bin/env python3
"""
TLS Session Parser using dpkt
解析TLS会话，提取random和加密载荷
"""

import dpkt
import sys


def parse_tls_handshake(handshake_data):
    """
    解析TLS握手消息，提取random
    Parse TLS handshake messages to extract random values
    """
    try:
        # TLS握手消息格式：
        # Handshake Type (1 byte) + Length (3 bytes) + Handshake Message
        if len(handshake_data) < 4:
            return None
        
        handshake_type = handshake_data[0]
        length = int.from_bytes(handshake_data[1:4], byteorder='big')
        
        result = {
            'handshake_type': handshake_type,
            'length': length,
            'random': None
        }
        
        # Client Hello (0x01) 或 Server Hello (0x02)
        if handshake_type in [0x01, 0x02] and len(handshake_data) >= 38:
            # 跳过: Handshake Type (1) + Length (3) + Version (2) = 6 bytes
            # Random 在偏移 6 开始，长度32字节
            random_offset = 6
            if len(handshake_data) >= random_offset + 32:
                random = handshake_data[random_offset:random_offset + 32]
                result['random'] = random
                result['handshake_type_name'] = 'ClientHello' if handshake_type == 0x01 else 'ServerHello'
        
        return result
    except Exception as e:
        print(f"Error parsing handshake: {e}", file=sys.stderr)
        return None


def parse_tls_record(record_data):
    """
    解析TLS记录层
    Parse TLS record layer
    """
    try:
        if len(record_data) < 5:
            return None
        
        # TLS记录格式：
        # Content Type (1 byte) + Version (2 bytes) + Length (2 bytes) + Fragment
        content_type = record_data[0]
        version = int.from_bytes(record_data[1:3], byteorder='big')
        length = int.from_bytes(record_data[3:5], byteorder='big')
        
        result = {
            'content_type': content_type,
            'version': version,
            'length': length,
            'fragment': record_data[5:5+length] if len(record_data) >= 5+length else None
        }
        
        # Content Type 定义:
        # 20 = ChangeCipherSpec, 21 = Alert, 22 = Handshake, 23 = Application Data
        content_type_names = {
            20: 'ChangeCipherSpec',
            21: 'Alert',
            22: 'Handshake',
            23: 'ApplicationData'
        }
        result['content_type_name'] = content_type_names.get(content_type, f'Unknown({content_type})')
        
        return result
    except Exception as e:
        print(f"Error parsing TLS record: {e}", file=sys.stderr)
        return None


def hex_dump(data, prefix=""):
    """
    以十六进制格式打印数据
    Print data in hexadecimal format
    """
    if data is None:
        return ""
    
    hex_str = data.hex()
    # 每行16字节，以空格分隔每个字节
    formatted = ""
    for i in range(0, len(hex_str), 32):  # 32个十六进制字符 = 16字节
        line = hex_str[i:i+32]
        # 每2个字符（1字节）添加空格
        formatted_line = ' '.join([line[j:j+2] for j in range(0, len(line), 2)])
        formatted += f"{prefix}{formatted_line}\n"
    return formatted.rstrip()


def parse_pcap(pcap_file):
    """
    解析PCAP文件，识别TLS会话
    Parse PCAP file to identify TLS sessions
    """
    print(f"正在解析PCAP文件: {pcap_file}\n")
    print("=" * 80)
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            packet_num = 0
            tls_session_count = 0
            
            for timestamp, buf in pcap:
                packet_num += 1
                
                try:
                    # 解析以太网帧
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # 检查是否是IP包
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    
                    ip = eth.data
                    
                    # 检查是否是TCP包
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    
                    tcp = ip.data
                    
                    # 检查TCP数据长度
                    if len(tcp.data) == 0:
                        continue
                    
                    # 尝试解析TLS记录
                    # TLS记录以Content Type开始: 20-23是有效的TLS Content Types
                    if tcp.data[0] in [20, 21, 22, 23]:
                        tls_session_count += 1
                        
                        print(f"\n{'#' * 80}")
                        print(f"TLS会话 #{tls_session_count} (数据包 #{packet_num})")
                        print(f"{'#' * 80}")
                        print(f"源地址: {dpkt.utils.inet_to_str(ip.src)}:{tcp.sport}")
                        print(f"目标地址: {dpkt.utils.inet_to_str(ip.dst)}:{tcp.dport}")
                        print(f"时间戳: {timestamp}")
                        print()
                        
                        # 解析TLS记录
                        offset = 0
                        record_num = 0
                        
                        while offset < len(tcp.data):
                            record_data = tcp.data[offset:]
                            record = parse_tls_record(record_data)
                            
                            if record is None:
                                break
                            
                            record_num += 1
                            print(f"--- TLS记录 #{record_num} ---")
                            print(f"内容类型: {record['content_type_name']} (0x{record['content_type']:02x})")
                            print(f"版本: 0x{record['version']:04x}")
                            print(f"长度: {record['length']} bytes")
                            
                            # 如果是握手消息，提取random
                            if record['content_type'] == 22 and record['fragment']:  # Handshake
                                handshake = parse_tls_handshake(record['fragment'])
                                if handshake and handshake['random']:
                                    print(f"\n【Random值】 ({handshake['handshake_type_name']}):")
                                    print(hex_dump(handshake['random'], "  "))
                            
                            # 如果是加密数据，打印载荷
                            if record['content_type'] == 23 and record['fragment']:  # Application Data (加密载荷)
                                print(f"\n【加密载荷】 (十六进制):")
                                print(hex_dump(record['fragment'], "  "))
                            
                            print()
                            
                            # 移动到下一个记录
                            offset += 5 + record['length']
                            
                            # 安全检查，避免无限循环
                            if offset >= len(tcp.data) or record['length'] == 0:
                                break
                
                except Exception as e:
                    # 跳过无法解析的包
                    continue
            
            print("\n" + "=" * 80)
            print(f"解析完成: 共 {packet_num} 个数据包, 发现 {tls_session_count} 个TLS记录")
            print("=" * 80)
    
    except FileNotFoundError:
        print(f"错误: 找不到文件 {pcap_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python3 tls_parser.py <pcap_file>")
        print("Usage: python3 tls_parser.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    parse_pcap(pcap_file)


if __name__ == "__main__":
    main()
