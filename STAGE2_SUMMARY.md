# 阶段二完成总结 (Stage 2 Completion Summary)

## ✅ 任务完成状态 (Task Completion Status)

### PCAP转存功能 - SHA256哈希处理 ✅

**目标：** 将源PCAP的加密数据解密后转存到一个新的PCAP的TCP流中。为了快速完成框架，现在实现把源TLS的加密载荷进行SHA256后，把SHA256的值转存到一个新的PCAP文件的新的TCP流中保存。

#### 三个核心要求全部完成 (All Three Requirements Completed)

1. ✅ **通信双方的IP和端口不变**
   - 保持原始源IP地址和端口
   - 保持原始目标IP地址和端口
   - 完全复制原始网络层信息

2. ✅ **每个TCP包的PCAP的时间戳不变**
   - 精确保持原始时间戳
   - 确保时间顺序一致
   - 便于后续分析和关联

3. ✅ **加密载荷进行SHA256哈希处理**
   - 提取TLS Application Data中的加密载荷
   - 计算SHA256哈希值（32字节）
   - 将哈希值作为新TCP包的载荷

## 🔧 技术实现 (Technical Implementation)

### 核心功能函数

```python
def save_hashed_pcap(pcap_file, output_file):
    """
    读取PCAP文件，提取TLS加密载荷，计算SHA256哈希，保存到新PCAP文件
    
    要求:
    1. 通信双方的IP和端口不变
    2. 每个TCP包的PCAP的时间戳不变
    3. TCP载荷为原始加密载荷的SHA256哈希值
    """
```

### 处理流程

1. **读取原始PCAP文件**
   - 使用dpkt.pcap.Reader读取数据包
   - 解析以太网帧、IP层、TCP层

2. **识别TLS Application Data**
   - 检查Content Type是否为0x17 (Application Data)
   - 解析TLS记录层，提取加密载荷fragment

3. **计算SHA256哈希**
   - 使用hashlib.sha256()计算加密载荷的哈希
   - 得到32字节的哈希值

4. **创建新的数据包**
   - 创建新的TCP包，载荷为SHA256哈希
   - 保持原始TCP标志、序列号等
   - 创建新的IP包，保持原始IP地址
   - 创建新的以太网帧

5. **写入新PCAP文件**
   - 使用dpkt.pcap.Writer写入
   - 保持原始时间戳

## 📝 使用方法 (Usage)

### 基本用法

```bash
# 转存PCAP文件
python3 tls_parser.py <input_pcap> <output_pcap>

# 示例
python3 tls_parser.py sample_tls.pcap output_hashed.pcap
```

### 参数说明

- `<input_pcap>`: 输入的PCAP文件路径，包含TLS加密流量
- `<output_pcap>`: 输出的PCAP文件路径，将保存处理后的数据包

### 兼容性

程序同时支持两种模式：

```bash
# 模式1: 仅解析和显示（阶段一功能）
python3 tls_parser.py sample_tls.pcap

# 模式2: 转存PCAP（阶段二功能）
python3 tls_parser.py sample_tls.pcap output.pcap
```

## 🔍 输出示例 (Output Example)

### 转存过程输出

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

### 验证输出结果

可以使用以下Python代码验证输出文件：

```python
import dpkt

with open('output_hashed.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for i, (timestamp, buf) in enumerate(pcap, 1):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        print(f'数据包 #{i}:')
        print(f'  源地址: {dpkt.utils.inet_to_str(ip.src)}:{tcp.sport}')
        print(f'  目标地址: {dpkt.utils.inet_to_str(ip.dst)}:{tcp.dport}')
        print(f'  时间戳: {timestamp}')
        print(f'  TCP载荷(SHA256): {tcp.data.hex()}')
```

## 🧪 测试验证 (Testing)

### 运行测试

```bash
# 运行阶段二功能测试
python3 test_save_pcap.py
```

### 测试内容

测试脚本验证三个核心要求：

1. **IP和端口验证**
   - 比较原始和输出数据包的源/目标IP
   - 比较原始和输出数据包的源/目标端口

2. **时间戳验证**
   - 确保时间戳精确匹配（允许浮点误差）

3. **SHA256哈希验证**
   - 独立计算原始载荷的SHA256
   - 与输出文件中的载荷进行比对

### 测试输出示例

```
================================================================================
测试PCAP转存功能 - SHA256哈希
Testing PCAP Save Functionality - SHA256 Hashing
================================================================================

要求1: 通信双方的IP和端口不变
  ✓ 数据包 #1: 192.168.1.100:54321 -> 93.184.216.34:443 (匹配)
  结果: 通过 ✓

要求2: 每个TCP包的PCAP的时间戳不变
  ✓ 数据包 #1: 时间戳 1760423629.866338 (匹配)
  结果: 通过 ✓

要求3: TCP载荷为原始加密载荷的SHA256哈希值
  ✓ 数据包 #1: SHA256匹配
    原始载荷长度: 64 bytes
    SHA256哈希: f0c18679934f9a97bf750471c16f744a19678f4541a70acea12a3b899fa60c60
  结果: 通过 ✓

================================================================================
🎉 所有测试通过! (All tests passed!)
================================================================================
```

## 📊 性能特点 (Performance Characteristics)

### 数据包处理

- **输入过滤**: 仅处理包含TLS Application Data的数据包
- **载荷转换**: 加密载荷（可变长度）→ SHA256哈希（固定32字节）
- **保持结构**: 完整保留网络层和传输层信息

### 示例转换

```
原始数据包:
  - 以太网帧: 14 bytes
  - IP层: 20 bytes
  - TCP层: 20 bytes
  - TCP载荷: 64 bytes (加密数据)
  总大小: 118 bytes

输出数据包:
  - 以太网帧: 14 bytes
  - IP层: 20 bytes
  - TCP层: 20 bytes
  - TCP载荷: 32 bytes (SHA256哈希)
  总大小: 86 bytes
```

## 🎯 应用场景 (Use Cases)

1. **快速验证框架**
   - 在实现真正的解密功能之前
   - 验证PCAP转存的基础架构
   - 确保网络层信息正确保持

2. **加密载荷指纹识别**
   - 使用SHA256作为加密载荷的唯一标识
   - 便于检测重复或相似的加密内容
   - 隐私保护：不暴露原始加密数据

3. **流量分析**
   - 简化数据包大小
   - 便于统计和可视化
   - 保持时序和连接关系

## 🔄 与阶段一的关系 (Relationship with Stage 1)

阶段一完成的功能仍然保留：

```bash
# 阶段一功能：解析和显示TLS会话
python3 tls_parser.py sample_tls.pcap

# 阶段二功能：转存PCAP文件
python3 tls_parser.py sample_tls.pcap output.pcap
```

两种模式通过命令行参数数量自动切换，无需修改代码。

## 📈 下一步计划 (Next Steps)

阶段二完成后，将进入阶段三：

- [ ] 集成keylog文件支持
- [ ] 实现真正的TLS解密功能
- [ ] 支持国密(SM)密码套件
- [ ] 将解密后的明文保存到PCAP文件
- [ ] 替换当前的SHA256哈希为解密后的明文

## 🏗️ 代码结构 (Code Structure)

### 新增文件

- `test_save_pcap.py` - 阶段二功能测试脚本
- `STAGE2_SUMMARY.md` - 本文档

### 修改文件

- `tls_parser.py` - 添加`save_hashed_pcap()`函数和命令行参数处理
- `README.md` - 更新功能特性和使用方法
- `USAGE.md` - 添加阶段二使用指南

### 导入的新模块

```python
import hashlib  # 用于SHA256哈希计算
```

## ✨ 关键代码片段 (Key Code Snippets)

### SHA256哈希计算

```python
# 计算SHA256哈希
sha256_hash = hashlib.sha256(record['fragment']).digest()
```

### 创建新TCP包

```python
# 创建新的TCP包，载荷为SHA256哈希值
new_tcp = dpkt.tcp.TCP(
    sport=tcp.sport,
    dport=tcp.dport,
    seq=tcp.seq,
    ack=tcp.ack,
    flags=tcp.flags,
    win=tcp.win,
    data=sha256_hash
)
```

### 保持时间戳

```python
# 写入新PCAP文件，保持原始时间戳
pcap_writer.writepkt(new_eth, ts=timestamp)
```

## 📚 相关文档 (Related Documentation)

- [README.md](README.md) - 项目主文档
- [USAGE.md](USAGE.md) - 详细使用指南
- [STAGE1_SUMMARY.md](STAGE1_SUMMARY.md) - 阶段一完成总结

## 🎓 技术要点 (Technical Highlights)

1. **最小化修改**: 仅添加新功能，不影响现有功能
2. **向后兼容**: 保留阶段一的所有功能
3. **精确保持**: IP、端口、时间戳完全不变
4. **标准格式**: 输出的PCAP文件符合标准格式，可被任何PCAP工具读取
5. **测试覆盖**: 完整的自动化测试验证所有要求

---

**完成日期**: 2025-10-14  
**版本**: Stage 2 - SHA256 Hashing
