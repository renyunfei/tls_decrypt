# 使用指南 (Usage Guide)

## 阶段一完成情况 (Stage 1 Completion)

### ✅ 已完成的三个任务 (Three Completed Tasks)

#### 1. 使用dpkt识别并解析TLS会话
程序能够：
- 读取pcap文件中的网络数据包
- 识别TCP/IP层的TLS流量
- 解析TLS记录层（Content Type, Version, Length）
- 显示源/目标IP地址和端口
- 显示时间戳信息

#### 2. 识别并解析Random
程序能够：
- 从ClientHello消息中提取32字节Random值
- 从ServerHello消息中提取32字节Random值
- 清晰标注Random值来源（ClientHello或ServerHello）
- 以十六进制格式显示Random值

#### 3. 识别并解析加密载荷，十六进制打印
程序能够：
- 识别TLS ApplicationData（加密载荷）
- 提取完整的加密数据
- 以十六进制格式打印，每行16字节
- 格式化输出，便于阅读

## 阶段二完成情况 (Stage 2 Completion)

### ✅ PCAP转存功能 (PCAP Save Functionality)

#### 功能描述
程序现在支持将TLS加密载荷进行SHA256哈希处理后，保存到新的PCAP文件中。

#### 实现的要求
1. ✅ **通信双方的IP和端口不变** - 保持原始源/目标IP地址和端口
2. ✅ **每个TCP包的PCAP的时间戳不变** - 精确保持原始时间戳
3. ✅ **SHA256哈希处理** - 对加密载荷计算SHA256，将32字节哈希值作为新的TCP载荷

#### 使用方法
```bash
# 转存PCAP文件，将加密载荷替换为SHA256哈希
python3 tls_parser.py <input_pcap> <output_pcap>

# 示例
python3 tls_parser.py sample_tls.pcap output_hashed.pcap
```

## 快速开始 (Quick Start)

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 创建测试数据
```bash
python3 create_sample_pcap.py
```
这将创建 `sample_tls.pcap` 文件，包含：
- 1个ClientHello（带Random值）
- 1个ServerHello（带Random值）
- 1个加密应用数据包

### 3. 运行解析器（仅查看）
```bash
python3 tls_parser.py sample_tls.pcap
```

### 4. 转存PCAP文件（SHA256哈希）
```bash
python3 tls_parser.py sample_tls.pcap output_hashed.pcap
```

### 5. 运行测试验证
```bash
# 测试阶段一功能
python3 test_parser.py

# 测试阶段二（PCAP转存）功能
python3 test_save_pcap.py
```

## 输出示例说明 (Output Explanation)

### TLS会话信息
```
################################################################################
TLS会话 #1 (数据包 #1)
################################################################################
源地址: 192.168.1.100:54321
目标地址: 93.184.216.34:443
时间戳: 1760423629.666338
```
- **TLS会话编号**: 当前是第几个TLS会话
- **数据包编号**: 在pcap文件中的数据包序号
- **源地址/目标地址**: IP地址和端口号
- **时间戳**: Unix时间戳

### TLS记录信息
```
--- TLS记录 #1 ---
内容类型: Handshake (0x16)
版本: 0x0303
长度: 45 bytes
```
- **内容类型**: Handshake(握手), ApplicationData(应用数据), Alert(警报)等
- **版本**: TLS版本（0x0303 = TLS 1.2）
- **长度**: 载荷长度（字节）

### Random值显示
```
【Random值】 (ClientHello):
  68 ed ee cd b4 e3 43 d6 e0 70 6b 28 8c 3b bd 7a
  f0 72 bd 18 b1 9e fd 5b 44 e8 e9 73 c8 12 48 08
```
- 32字节Random值
- 每行16字节
- 标注来源（ClientHello或ServerHello）

### 加密载荷显示
```
【加密载荷】 (十六进制):
  d0 75 a0 df 80 ed 85 2c b8 f6 0a 9a 91 6d bf 41
  d3 98 cb 9a 70 62 dc 47 7f 9a e9 c4 2d 0f f7 67
  a3 45 16 71 ce 17 5f 8b 89 4f a7 93 10 13 f4 4c
  a5 d0 f8 cc 4a 45 66 6d 6c 87 e3 f6 46 20 56 8f
```
- 完整的加密数据
- 十六进制格式
- 每行16字节，便于阅读

## 使用自己的PCAP文件 (Using Your Own PCAP)

### 仅解析模式
如果您想查看TLS会话信息：

```bash
python3 tls_parser.py your_capture.pcap
```

程序会自动：
1. 扫描所有数据包
2. 识别TLS流量（基于Content Type）
3. 解析并显示所有TLS会话
4. 提取Random值（如果有握手消息）
5. 显示加密载荷（如果有应用数据）

### 转存模式
如果您想将加密载荷转换为SHA256哈希并保存：

```bash
python3 tls_parser.py your_capture.pcap output_hashed.pcap
```

程序会：
1. 扫描所有数据包
2. 识别TLS Application Data（加密载荷）
3. 计算每个加密载荷的SHA256哈希
4. 创建新的TCP包，载荷为32字节SHA256哈希
5. 保持原始IP、端口和时间戳不变
6. 保存到新的PCAP文件

## 支持的TLS版本 (Supported TLS Versions)

当前程序支持所有标准TLS版本的记录层解析：
- TLS 1.0 (0x0301)
- TLS 1.1 (0x0302)
- TLS 1.2 (0x0303)
- TLS 1.3 (0x0304)

## 注意事项 (Notes)

1. **阶段性开发**: 当前仅完成第一阶段任务，后续将添加解密功能
2. **国密支持**: 下一阶段将添加SM（国密）密码套件支持
3. **Keylog集成**: 下一阶段将集成keylog文件进行解密
4. **性能**: 对于大型pcap文件，处理可能需要一些时间

## 故障排除 (Troubleshooting)

### 如果看不到TLS会话
- 确认pcap文件包含TLS流量
- 检查端口是否为标准TLS端口（443, 8443等）
- 确认数据包包含TCP/IP层

### 如果看不到Random值
- 确认pcap文件包含TLS握手消息（ClientHello/ServerHello）
- 握手消息长度必须足够（至少38字节）

### 如果看不到加密载荷
- 确认pcap文件包含TLS ApplicationData
- 检查TLS会话是否完成握手并开始传输数据

## 转存功能输出示例 (Save Functionality Output Example)

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

**说明：**
- 原始加密载荷长度: 64 bytes
- SHA256哈希长度: 32 bytes
- 保持了原始的IP地址、端口和时间戳
- 仅保存包含Application Data的数据包

## 下一步 (Next Steps)

已完成阶段二。后续将进行：
- 阶段三: 集成keylog文件
- 阶段四: 实现真正的解密功能
- 阶段五: 支持国密密码套件
- 阶段六: 将解密后的数据保存到PCAP文件
