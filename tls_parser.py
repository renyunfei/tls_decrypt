#!/usr/bin/env python3
"""
TLS Session Parser using dpkt
解析TLS会话，提取random和加密载荷
"""

import dpkt
import sys
import hashlib


class TLSHandshake:
    """TLS握手消息类 / TLS Handshake Message Class"""
    
    def __init__(self, handshake_data):
        """
        初始化TLS握手消息
        Initialize TLS handshake message
        """
        self.handshake_type = None
        self.length = None
        self.random = None
        self.handshake_type_name = None
        self._parse(handshake_data)
    
    def _parse(self, handshake_data):
        """
        解析TLS握手消息，提取random
        Parse TLS handshake messages to extract random values
        """
        try:
            # TLS握手消息格式：
            # Handshake Type (1 byte) + Length (3 bytes) + Handshake Message
            if len(handshake_data) < 4:
                return
            
            self.handshake_type = handshake_data[0]
            self.length = int.from_bytes(handshake_data[1:4], byteorder='big')
            
            # Client Hello (0x01) 或 Server Hello (0x02)
            if self.handshake_type in [0x01, 0x02] and len(handshake_data) >= 38:
                # 跳过: Handshake Type (1) + Length (3) + Version (2) = 6 bytes
                # Random 在偏移 6 开始，长度32字节
                random_offset = 6
                if len(handshake_data) >= random_offset + 32:
                    self.random = handshake_data[random_offset:random_offset + 32]
                    self.handshake_type_name = 'ClientHello' if self.handshake_type == 0x01 else 'ServerHello'
        
        except Exception as e:
            print(f"Error parsing handshake: {e}", file=sys.stderr)
    
    def is_valid(self):
        """检查握手消息是否有效 / Check if handshake message is valid"""
        return self.handshake_type is not None


class TLSRecord:
    """TLS记录层类 / TLS Record Layer Class"""
    
    # Content Type 定义 / Content Type definitions
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    CONTENT_TYPE_NAMES = {
        20: 'ChangeCipherSpec',
        21: 'Alert',
        22: 'Handshake',
        23: 'ApplicationData'
    }
    
    def __init__(self, record_data):
        """
        初始化TLS记录
        Initialize TLS record
        """
        self.content_type = None
        self.version = None
        self.length = None
        self.fragment = None
        self.content_type_name = None
        self._parse(record_data)
    
    def _parse(self, record_data):
        """
        解析TLS记录层
        Parse TLS record layer
        """
        try:
            if len(record_data) < 5:
                return
            
            # TLS记录格式：
            # Content Type (1 byte) + Version (2 bytes) + Length (2 bytes) + Fragment
            self.content_type = record_data[0]
            self.version = int.from_bytes(record_data[1:3], byteorder='big')
            self.length = int.from_bytes(record_data[3:5], byteorder='big')
            self.fragment = record_data[5:5+self.length] if len(record_data) >= 5+self.length else None
            self.content_type_name = self.CONTENT_TYPE_NAMES.get(self.content_type, f'Unknown({self.content_type})')
        
        except Exception as e:
            print(f"Error parsing TLS record: {e}", file=sys.stderr)
    
    def is_valid(self):
        """检查记录是否有效 / Check if record is valid"""
        return self.content_type is not None
    
    def is_handshake(self):
        """检查是否是握手消息 / Check if this is a handshake message"""
        return self.content_type == self.HANDSHAKE
    
    def is_application_data(self):
        """检查是否是应用数据 / Check if this is application data"""
        return self.content_type == self.APPLICATION_DATA
    
    def get_handshake(self):
        """获取握手消息对象 / Get handshake message object"""
        if self.is_handshake() and self.fragment:
            return TLSHandshake(self.fragment)
        return None


class HexFormatter:
    """十六进制格式化工具类 / Hexadecimal Formatter Utility Class"""
    
    @staticmethod
    def format(data, prefix=""):
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


# Legacy function wrappers for backward compatibility
def parse_tls_handshake(handshake_data):
    """
    解析TLS握手消息，提取random (向后兼容的包装函数)
    Parse TLS handshake messages to extract random values (backward compatibility wrapper)
    """
    handshake = TLSHandshake(handshake_data)
    if handshake.is_valid():
        return {
            'handshake_type': handshake.handshake_type,
            'length': handshake.length,
            'random': handshake.random,
            'handshake_type_name': handshake.handshake_type_name
        }
    return None


def parse_tls_record(record_data):
    """
    解析TLS记录层 (向后兼容的包装函数)
    Parse TLS record layer (backward compatibility wrapper)
    """
    record = TLSRecord(record_data)
    if record.is_valid():
        return {
            'content_type': record.content_type,
            'version': record.version,
            'length': record.length,
            'fragment': record.fragment,
            'content_type_name': record.content_type_name
        }
    return None


def hex_dump(data, prefix=""):
    """
    以十六进制格式打印数据 (向后兼容的包装函数)
    Print data in hexadecimal format (backward compatibility wrapper)
    """
    return HexFormatter.format(data, prefix)


class TLSParser:
    """TLS协议解析器类 / TLS Protocol Parser Class"""
    
    def __init__(self):
        """初始化TLS解析器 / Initialize TLS parser"""
        self.packet_count = 0
        self.tls_session_count = 0
    
    def parse_pcap(self, pcap_file):
        """
        解析PCAP文件，识别TLS会话
        Parse PCAP file to identify TLS sessions
        """
        print(f"正在解析PCAP文件: {pcap_file}\n")
        print("=" * 80)
        
        try:
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    self.packet_count += 1
                    
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
                            self._process_tls_packet(timestamp, ip, tcp)
                    
                    except Exception as e:
                        # 跳过无法解析的包
                        continue
                
                print("\n" + "=" * 80)
                print(f"解析完成: 共 {self.packet_count} 个数据包, 发现 {self.tls_session_count} 个TLS记录")
                print("=" * 80)
        
        except FileNotFoundError:
            print(f"错误: 找不到文件 {pcap_file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _process_tls_packet(self, timestamp, ip, tcp):
        """
        处理单个TLS数据包
        Process a single TLS packet
        """
        self.tls_session_count += 1
        
        print(f"\n{'#' * 80}")
        print(f"TLS会话 #{self.tls_session_count} (数据包 #{self.packet_count})")
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
            record = TLSRecord(record_data)
            
            if not record.is_valid():
                break
            
            record_num += 1
            self._display_tls_record(record, record_num)
            
            # 移动到下一个记录
            offset += 5 + record.length
            
            # 安全检查，避免无限循环
            if offset >= len(tcp.data) or record.length == 0:
                break
    
    def _display_tls_record(self, record, record_num):
        """
        显示TLS记录信息
        Display TLS record information
        """
        print(f"--- TLS记录 #{record_num} ---")
        print(f"内容类型: {record.content_type_name} (0x{record.content_type:02x})")
        print(f"版本: 0x{record.version:04x}")
        print(f"长度: {record.length} bytes")
        
        # 如果是握手消息，提取random
        if record.is_handshake() and record.fragment:
            handshake = record.get_handshake()
            if handshake and handshake.random:
                print(f"\n【Random值】 ({handshake.handshake_type_name}):")
                print(HexFormatter.format(handshake.random, "  "))
        
        # 如果是加密数据，打印载荷
        if record.is_application_data() and record.fragment:
            print(f"\n【加密载荷】 (十六进制):")
            print(HexFormatter.format(record.fragment, "  "))
        
        print()


class PCAPProcessor:
    """PCAP文件处理器类 / PCAP File Processor Class"""
    
    def __init__(self):
        """初始化PCAP处理器 / Initialize PCAP processor"""
        self.packet_count = 0
        self.saved_packet_count = 0
        self.handshake_count = 0
        self.teardown_count = 0
        self.next_seq_by_direction = {}
        self.current_seq_by_direction = {}
        self.seen_syn = False
        self.seen_syn_ack = False
        self.handshake_complete = False
        self.teardown_started = False
    
    def save_hashed_pcap(self, pcap_file, output_file):
        """
        读取PCAP文件，提取TLS加密载荷，计算SHA256哈希，保存到新PCAP文件
        Read PCAP file, extract TLS encrypted payloads, compute SHA256 hash, save to new PCAP file
        
        要求:
        1. 通信双方的IP和端口不变
        2. 每个TCP包的PCAP的时间戳不变
        3. TCP载荷为原始加密载荷的SHA256哈希值
        4. 保存TCP三次握手和四次挥手报文
        5. 修正TCP序列号和确认号，确保一致性
        """
        print(f"正在处理PCAP文件: {pcap_file}")
        print(f"输出文件: {output_file}\n")
        
        try:
            with open(pcap_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                pcap_reader = dpkt.pcap.Reader(f_in)
                pcap_writer = dpkt.pcap.Writer(f_out)
                
                for timestamp, buf in pcap_reader:
                    self.packet_count += 1
                    
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
                        
                        # 处理TCP握手和挥手
                        if self._process_tcp_control_packet(eth, ip, tcp, timestamp, pcap_writer):
                            continue
                        
                        # 处理TLS应用数据
                        self._process_tls_data_packet(eth, ip, tcp, timestamp, pcap_writer)
                    
                    except Exception as e:
                        # 跳过无法解析的包
                        continue
                
                self._print_summary(output_file)
        
        except FileNotFoundError:
            print(f"错误: 找不到文件 {pcap_file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _process_tcp_control_packet(self, eth, ip, tcp, timestamp, pcap_writer):
        """
        处理TCP控制包（握手和挥手）
        Process TCP control packets (handshake and teardown)
        返回True表示已处理此包
        """
        # 检查TCP标志
        has_syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        has_ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        has_fin = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        has_no_data = len(tcp.data) == 0
        
        # 更新连接状态
        if has_syn and not has_ack:
            self.seen_syn = True
        elif has_syn and has_ack:
            self.seen_syn_ack = True
        elif has_fin:
            self.teardown_started = True
        
        # 判断是否应该保存此包
        should_save = False
        packet_type = ""
        
        # 保存SYN和SYN-ACK（TCP握手的前两步）
        if has_syn:
            should_save = True
            packet_type = "TCP握手报文"
        # 保存FIN包（TCP挥手）
        elif has_fin:
            should_save = True
            packet_type = "TCP挥手报文"
        # 保存纯ACK包，但只在特定情况下：
        elif has_no_data and has_ack:
            if self.seen_syn_ack and not self.handshake_complete:
                # 这是TCP三次握手的第三个包
                should_save = True
                packet_type = "TCP握手报文"
                self.handshake_complete = True
            elif self.teardown_started:
                # 这是TCP挥手过程中的ACK
                should_save = True
                packet_type = "TCP挥手报文"
        
        if should_save:
            self._save_control_packet(eth, ip, tcp, timestamp, packet_type, pcap_writer)
            return True
        
        return False
    
    def _save_control_packet(self, eth, ip, tcp, timestamp, packet_type, pcap_writer):
        """
        保存TCP控制包
        Save TCP control packet
        """
        # 定义连接的键
        src_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        dst_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
        
        # 如果这是第一次看到这个方向的包，初始化映射
        if src_key not in self.current_seq_by_direction:
            self.current_seq_by_direction[src_key] = tcp.seq
            self.next_seq_by_direction[src_key] = tcp.seq
        
        # 获取应该使用的序列号
        use_seq = self.next_seq_by_direction[src_key]
        
        # 获取ACK号（参考对方的下一个期望序列号）
        use_ack = self.next_seq_by_direction.get(dst_key, tcp.ack) if tcp.ack > 0 else 0
        
        # 计算这个包消耗的序列号空间
        seq_consumed = len(tcp.data)
        if tcp.flags & dpkt.tcp.TH_SYN:
            seq_consumed += 1
        if tcp.flags & dpkt.tcp.TH_FIN:
            seq_consumed += 1
        
        # 更新下一个期望的序列号
        self.next_seq_by_direction[src_key] = use_seq + seq_consumed
        
        # 保存TCP握手/挥手报文
        new_tcp = dpkt.tcp.TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            seq=use_seq,
            ack=use_ack,
            flags=tcp.flags,
            win=tcp.win,
            data=tcp.data
        )
        
        new_ip = dpkt.ip.IP(
            src=ip.src,
            dst=ip.dst,
            p=dpkt.ip.IP_PROTO_TCP,
            data=new_tcp
        )
        
        new_eth = dpkt.ethernet.Ethernet(
            dst=eth.dst,
            src=eth.src,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=new_ip
        )
        
        pcap_writer.writepkt(new_eth, ts=timestamp)
        self.saved_packet_count += 1
        
        # 更新计数
        if packet_type == "TCP握手报文":
            self.handshake_count += 1
        elif packet_type == "TCP挥手报文":
            self.teardown_count += 1
        
        self._print_control_packet_info(ip, tcp, timestamp, packet_type, use_seq, use_ack)
    
    def _process_tls_data_packet(self, eth, ip, tcp, timestamp, pcap_writer):
        """
        处理TLS数据包
        Process TLS data packets
        """
        # 检查TCP数据长度
        if len(tcp.data) == 0:
            return
        
        # 尝试解析TLS记录
        if tcp.data[0] in [20, 21, 22, 23]:
            offset = 0
            
            while offset < len(tcp.data):
                record_data = tcp.data[offset:]
                record = TLSRecord(record_data)
                
                if not record.is_valid():
                    break
                
                # 如果是加密数据（Application Data），计算SHA256并保存
                if record.is_application_data() and record.fragment:
                    self._save_hashed_data_packet(eth, ip, tcp, timestamp, record.fragment, pcap_writer)
                
                # 移动到下一个记录
                offset += 5 + record.length
                
                # 安全检查，避免无限循环
                if offset >= len(tcp.data) or record.length == 0:
                    break
    
    def _save_hashed_data_packet(self, eth, ip, tcp, timestamp, fragment, pcap_writer):
        """
        保存哈希后的数据包
        Save hashed data packet
        """
        # 计算SHA256哈希
        sha256_hash = hashlib.sha256(fragment).digest()
        
        # 定义连接的键
        src_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        dst_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
        
        # 如果这是第一次看到这个方向的包，初始化映射
        if src_key not in self.current_seq_by_direction:
            self.current_seq_by_direction[src_key] = tcp.seq
            self.next_seq_by_direction[src_key] = tcp.seq
        
        # 获取应该使用的序列号
        use_seq = self.next_seq_by_direction[src_key]
        
        # 获取ACK号（参考对方的下一个期望序列号）
        use_ack = self.next_seq_by_direction.get(dst_key, tcp.ack) if tcp.ack > 0 else 0
        
        # 计算这个包消耗的序列号空间（使用新的数据长度）
        seq_consumed = len(sha256_hash)
        
        # 更新下一个期望的序列号
        self.next_seq_by_direction[src_key] = use_seq + seq_consumed
        
        # 创建新的TCP包，载荷为SHA256哈希值
        new_tcp = dpkt.tcp.TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            seq=use_seq,
            ack=use_ack,
            flags=tcp.flags,
            win=tcp.win,
            data=sha256_hash
        )
        
        # 创建新的IP包
        new_ip = dpkt.ip.IP(
            src=ip.src,
            dst=ip.dst,
            p=dpkt.ip.IP_PROTO_TCP,
            data=new_tcp
        )
        
        # 创建新的以太网帧
        new_eth = dpkt.ethernet.Ethernet(
            dst=eth.dst,
            src=eth.src,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=new_ip
        )
        
        # 写入新PCAP文件，保持原始时间戳
        pcap_writer.writepkt(new_eth, ts=timestamp)
        self.saved_packet_count += 1
        
        self._print_data_packet_info(ip, tcp, timestamp, len(tcp.data), len(sha256_hash), use_seq, use_ack, sha256_hash)
    
    def _print_control_packet_info(self, ip, tcp, timestamp, packet_type, use_seq, use_ack):
        """打印控制包信息 / Print control packet information"""
        print(f"数据包 #{self.packet_count}: 保存{packet_type}")
        print(f"  源地址: {dpkt.utils.inet_to_str(ip.src)}:{tcp.sport}")
        print(f"  目标地址: {dpkt.utils.inet_to_str(ip.dst)}:{tcp.dport}")
        print(f"  时间戳: {timestamp}")
        
        flags = []
        if tcp.flags & dpkt.tcp.TH_SYN:
            flags.append('SYN')
        if tcp.flags & dpkt.tcp.TH_ACK:
            flags.append('ACK')
        if tcp.flags & dpkt.tcp.TH_FIN:
            flags.append('FIN')
        print(f"  标志: {','.join(flags)}")
        
        if use_seq != tcp.seq or use_ack != tcp.ack:
            print(f"  序列号调整: seq {tcp.seq} -> {use_seq}, ack {tcp.ack} -> {use_ack}")
        print()
    
    def _print_data_packet_info(self, ip, tcp, timestamp, orig_len, new_len, use_seq, use_ack, sha256_hash):
        """打印数据包信息 / Print data packet information"""
        print(f"数据包 #{self.packet_count}: 保存SHA256哈希 ({orig_len} bytes -> {new_len} bytes)")
        print(f"  源地址: {dpkt.utils.inet_to_str(ip.src)}:{tcp.sport}")
        print(f"  目标地址: {dpkt.utils.inet_to_str(ip.dst)}:{tcp.dport}")
        print(f"  时间戳: {timestamp}")
        print(f"  原始seq: {tcp.seq}, 使用seq: {use_seq}")
        print(f"  原始ack: {tcp.ack}, 使用ack: {use_ack}")
        print(f"  SHA256: {sha256_hash.hex()}")
        print()
    
    def _print_summary(self, output_file):
        """打印处理摘要 / Print processing summary"""
        print("=" * 80)
        print(f"处理完成:")
        print(f"  输入数据包总数: {self.packet_count}")
        print(f"  保存到新PCAP的数据包数: {self.saved_packet_count}")
        print(f"    - TCP握手报文: {self.handshake_count}")
        print(f"    - TLS加密数据(SHA256): {self.saved_packet_count - self.handshake_count - self.teardown_count}")
        print(f"    - TCP挥手报文: {self.teardown_count}")
        print(f"  输出文件: {output_file}")
        print("=" * 80)


def save_hashed_pcap(pcap_file, output_file):
    """
    读取PCAP文件，提取TLS加密载荷，计算SHA256哈希，保存到新PCAP文件
    (向后兼容的包装函数)
    Read PCAP file, extract TLS encrypted payloads, compute SHA256 hash, save to new PCAP file
    (backward compatibility wrapper)
    """
    processor = PCAPProcessor()
    processor.save_hashed_pcap(pcap_file, output_file)


def parse_pcap(pcap_file):
    """
    解析PCAP文件，识别TLS会话 (向后兼容的包装函数)
    Parse PCAP file to identify TLS sessions (backward compatibility wrapper)
    """
    parser = TLSParser()
    parser.parse_pcap(pcap_file)


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python3 tls_parser.py <pcap_file> [output_pcap_file]")
        print("Usage: python3 tls_parser.py <pcap_file> [output_pcap_file]")
        print()
        print("参数说明:")
        print("  <pcap_file>         - 输入PCAP文件路径")
        print("  [output_pcap_file]  - (可选) 输出PCAP文件路径")
        print()
        print("如果提供输出文件路径，程序将:")
        print("  1. 提取TLS加密载荷")
        print("  2. 计算SHA256哈希")
        print("  3. 保存到新的PCAP文件（保持IP、端口、时间戳不变）")
        print()
        print("如果不提供输出文件路径，程序将只解析并显示TLS会话信息。")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # 如果提供了输出文件参数，执行转存功能
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
        save_hashed_pcap(pcap_file, output_file)
    else:
        # 否则只进行解析和显示
        parse_pcap(pcap_file)


if __name__ == "__main__":
    main()
