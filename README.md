# tls_decrypt

使用keylogfile解密国密pcap的tls流，并转存到一个新的pcap文件里

## 功能特性 (Features)

### 阶段一：TLS会话解析 (Stage 1: TLS Session Parsing) ✅
- ✅ 使用dpkt识别并解析TLS会话
- ✅ 识别并解析ClientHello和ServerHello中的Random值
- ✅ 识别并解析加密载荷，以十六进制格式打印

### 阶段二：PCAP转存功能 (Stage 2: PCAP Save Functionality) ✅
- ✅ 提取TLS加密载荷并计算SHA256哈希
- ✅ 将SHA256哈希值保存到新的PCAP文件
- ✅ 保持原始IP地址和端口不变
- ✅ 保持原始时间戳不变

### 未来阶段 (Future Stages)
- ⏳ 集成keylog文件进行解密
- ⏳ 支持国密(SM)密码套件
- ⏳ 将真正解密后的流量保存到新的pcap文件

## 安装依赖 (Installation)

```bash
pip install -r requirements.txt
```

## 使用方法 (Usage)

### 1. 解析TLS会话（仅查看）

```bash
python3 tls_parser.py <pcap_file>
```

### 2. 转存PCAP文件（SHA256哈希）

```bash
python3 tls_parser.py <input_pcap_file> <output_pcap_file>
```

此命令将：
1. 提取输入PCAP中的TLS加密载荷（Application Data）
2. 计算每个加密载荷的SHA256哈希值
3. 创建新的TCP数据包，载荷为SHA256哈希值（32字节）
4. 保存到新的PCAP文件，保持原始IP、端口和时间戳不变

**示例：**
```bash
python3 tls_parser.py sample_tls.pcap output_hashed.pcap
```

### 3. 创建示例PCAP文件（用于测试）

```bash
python3 create_sample_pcap.py
```

这将创建一个 `sample_tls.pcap` 文件，包含：
- Client Hello（带Random值）
- Server Hello（带Random值）
- 加密应用数据

### 4. 测试示例

```bash
# 仅解析和显示
python3 tls_parser.py sample_tls.pcap

# 转存到新PCAP文件
python3 tls_parser.py sample_tls.pcap output.pcap
```

## 输出示例 (Example Output)

### 解析模式输出

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

### 转存模式输出

```
正在处理PCAP文件: sample_tls.pcap
输出文件: output_hashed.pcap

数据包 #3: 保存SHA256哈希 (64 bytes -> 32 bytes)
  源地址: 192.168.1.100:54321
  目标地址: 93.184.216.34:443
  时间戳: 1760423629.866338
  SHA256: f0c18679934f9a97bf750471c16f744a19678f4541a70acea12a3b899fa60c60

================================================================================
处理完成:
  输入数据包总数: 3
  保存到新PCAP的数据包数: 1
  输出文件: output_hashed.pcap
================================================================================
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

### PCAP转存功能
- SHA256哈希计算
- 保持原始网络层信息（IP、端口、时间戳）
- 创建新的TCP流，载荷为哈希值

## 项目结构 (Project Structure)

```
tls_decrypt/
├── README.md                    # 项目文档
├── requirements.txt             # Python依赖
├── tls_parser.py               # TLS会话解析器（主程序）
├── create_sample_pcap.py       # 示例PCAP生成工具
├── test_parser.py              # 阶段一功能测试
├── test_save_pcap.py           # PCAP转存功能测试
└── sample_tls.pcap             # 示例PCAP文件（测试用）
```
