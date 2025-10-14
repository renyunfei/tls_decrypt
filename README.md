# tls_decrypt

使用keylogfile解密国密pcap的tls流，并转存到一个新的pcap文件里

## 功能特性 (Features)

### 阶段一：TLS会话解析 (Stage 1: TLS Session Parsing) ✅
- ✅ 使用dpkt识别并解析TLS会话
- ✅ 识别并解析ClientHello和ServerHello中的Random值
- ✅ 识别并解析加密载荷，以十六进制格式打印

### 未来阶段 (Future Stages)
- ⏳ 集成keylog文件进行解密
- ⏳ 支持国密(SM)密码套件
- ⏳ 将解密后的流量保存到新的pcap文件

## 安装依赖 (Installation)

```bash
pip install -r requirements.txt
```

## 使用方法 (Usage)

### 1. 解析TLS会话

```bash
python3 tls_parser.py <pcap_file>
```

### 2. 创建示例PCAP文件（用于测试）

```bash
python3 create_sample_pcap.py
```

这将创建一个 `sample_tls.pcap` 文件，包含：
- Client Hello（带Random值）
- Server Hello（带Random值）
- 加密应用数据

### 3. 测试示例

```bash
python3 tls_parser.py sample_tls.pcap
```

## 输出示例 (Example Output)

```
正在解析PCAP文件: sample_tls.pcap
================================================================================

################################################################################
TLS会话 #1 (数据包 #1)
################################################################################
源地址: 192.168.1.100:54321
目标地址: 93.184.216.34:443
时间戳: 1760423629.666338

--- TLS记录 #1 ---
内容类型: Handshake (0x16)
版本: 0x0303
长度: 45 bytes

【Random值】 (ClientHello):
  68 ed ee cd b4 e3 43 d6 e0 70 6b 28 8c 3b bd 7a
  f0 72 bd 18 b1 9e fd 5b 44 e8 e9 73 c8 12 48 08

...
```

## 技术细节 (Technical Details)

### TLS记录层解析
- Content Type识别（Handshake, ApplicationData等）
- 版本检测（TLS 1.0-1.3）
- 载荷长度解析

### 握手消息解析
- Client Hello / Server Hello识别
- Random值提取（32字节）
- 会话信息解析

### 加密载荷处理
- Application Data识别
- 十六进制格式化输出
- 每行16字节显示

## 项目结构 (Project Structure)

```
tls_decrypt/
├── README.md                    # 项目文档
├── requirements.txt             # Python依赖
├── tls_parser.py               # TLS会话解析器（主程序）
├── create_sample_pcap.py       # 示例PCAP生成工具
└── sample_tls.pcap             # 示例PCAP文件（测试用）
```
