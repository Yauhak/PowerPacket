# PowerPacket
- 一个基于C++实现的网络数据包解析与伪造工具，支持ARP欺骗和DNS劫持功能，用于网络安全实验或教学演示。
## ⚠️ 免责声明
- 本工具仅供学习、研究或授权测试使用。
- 禁止在未经许可的网络环境中使用此工具。
- 开发者不对滥用此工具的行为负责。
## License
[GNU GPL v3.0](LICENSE)
## 功能特性
- ARP欺骗：伪造ARP响应，实现中间人攻击模拟。
- DNS劫持：篡改DNS响应数据包，演示域名解析劫持。
- 支持多种协议解析：以太网/IPv4/TCP/UDP/ARP/DNS。
### 依赖项
- Npcap/WinPcap：数据包捕获库（Windows）
- pcap.h：需安装Npcap/WinPcap的SDK
- 编译器支持C++11
### 编译
- Linux/Windows
```bash
# 安装依赖（Linux示例）
sudo apt install libpcap-dev
# 编译
g++ main.cpp FalsifyPackets.cpp ProtocolHeaders.cpp -o packet_tool -lpcap
```
### 运行（可能需要管理员权限）
- Linux
```bash
sudo ./packet_tool
```
- Windows可直接以管理员身份运行编译好的可执行文件
### 使用说明
- 选择网卡并开启混杂模式
- 选择攻击类型（ARP/DNS）
- 输入攻击者IP/MAC和目标IP
- 工具将自动捕获并篡改指定流量
### 代码结构
```plaintext
├── main.cpp            # 主程序与交互逻辑
├── FalsifyPackets.cpp  # ARP/DNS数据包伪造实现
├── ProtocolHeaders.cpp # 协议解析工具库
├── *.h                 # 头文件定义
└── README.md           # 说明文档
```
### 当前限制
- 仅支持IPv4协议
- 需在局域网环境运行
- 未实现完整错误处理
### 开源协议
- GPL-3.0 License
# 华子（Yauhak），QQ 3953814837，写于2025.4

