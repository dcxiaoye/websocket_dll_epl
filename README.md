# 📚 WebSocket DLL for 易语言（EPL）—— 完整使用文档 v1.1

> 专为易语言打造的高性能 WebSocket 动态链接库
>  支持服务端/客户端、WS/WSS、AES-256-GCM 加密、防重放、心跳保活、自动重连等企业级特性

------
## 💰扫码赞助
<img src="./img/skm.png" width="300">
------

## ✅ 一、核心特性

| 类别         | 功能                                                         |
| ------------ | ------------------------------------------------------------ |
| **协议支持** | WebSocket (ws://) 与 Secure WebSocket (wss://, TLS 1.2+)     |
| **编码兼容** | 自动 GBK ↔ UTF-8 转换（适配易语言默认编码）                  |
| **安全机制** | AES-256-GCM 端到端加密 + 防重放攻击（±5 分钟窗口）           |
| **连接管理** | 心跳保活（Ping/Pong）、读超时断连、自动重连、最大连接数限制  |
| **通信能力** | 广播、定向发送、消息回调、连接/断开事件通知                  |
| **线程安全** | 内部使用 `parking_lot` + `tokio`，多线程调用无冲突           |
| **日志系统** | 支持控制台输出 + 文件日志（可配置级别：Error/Warn/Info/Debug） |

------

## ⚙️ 二、DLL 导出函数（共 25 个）

所有函数均为 `extern "system"`（即 `stdcall`），字符串参数为 **GBK 编码、C 风格 null-terminated 字符串**。

### 🔧 配置类

| 函数                     | 参数                  | 返回    | 说明                                             |
| ------------------------ | --------------------- | ------- | ------------------------------------------------ |
| `set_max_clients`        | `limit: usize`        | `()`    | 设置服务端最大并发连接数（默认 1000）            |
| `get_max_clients`        | —                     | `usize` | 获取当前最大连接数                               |
| `set_heartbeat_interval` | `seconds: u64`        | `()`    | 设置心跳间隔（秒，默认 30）                      |
| `get_heartbeat_interval` | —                     | `u64`   | 获取当前心跳间隔                                 |
| `set_read_timeout`       | `seconds: u64`        | `()`    | 设置读超时时间（秒，默认 60）                    |
| `get_read_timeout`       | —                     | `u64`   | 获取当前读超时时间                               |
| `set_replay_window`      | `seconds: i64`        | `()`    | 设置防重放时间窗口（±秒，默认 300 = ±5 分钟）    |
| `get_replay_window`      | —                     | `i64`   | 获取当前防重放窗口                               |
| `set_log_level`          | `level: u8`           | `()`    | 设置日志级别（0=Error, 1=Warn, 2=Info, 3=Debug） |
| `set_log_file_path`      | `path: *const c_char` | `bool`  | 设置日志文件路径（GBK）                          |

### 🔐 加密类

| 函数                        | 参数                               | 返回          | 说明                                       |
| --------------------------- | ---------------------------------- | ------------- | ------------------------------------------ |
| `set_server_encryption_key` | `key: *const c_char`               | `bool`        | 设置服务端 AES-256 密钥（32 字节原始数据） |
| `set_client_encryption_key` | `key: *const c_char`               | `bool`        | 设置客户端 AES-256 密钥（32 字节原始数据） |
| `enable_encryption`         | `enable: bool`                     | `()`          | 启用/禁用端到端加密                        |
| `is_encryption_enabled`     | —                                  | `bool`        | 查询是否启用加密                           |
| `encrypt_message`           | `message: *const c_char`           | `*mut c_char` | 手动加密文本（返回 Base64 密文）           |
| `decrypt_message`           | `encrypted_message: *const c_char` | `*mut c_char` | 手动解密文本（返回明文）                   |

### 🌐 连接类

| 函数                   | 参数                                                    | 返回   | 说明                                    |
| ---------------------- | ------------------------------------------------------- | ------ | --------------------------------------- |
| `set_skip_cert_verify` | `skip: bool`                                            | `()`   | 控制是否跳过 TLS 证书验证（⚠️ 仅测试用） |
| `start_ws_server`      | `bind_addr`, `use_wss`, `cert_pem_path`, `key_pem_path` | `bool` | 启动 WebSocket 服务端                   |
| `connect_ws_client`    | `server_url`, `enable_reconnect`                        | `bool` | 连接 WebSocket 客户端（支持自动重连）   |

### 📤 通信类

| 函数                      | 参数                       | 返回   | 说明                                     |
| ------------------------- | -------------------------- | ------ | ---------------------------------------- |
| `broadcast_to_clients`    | `message: *const c_char`   | `bool` | 广播消息给所有已连接客户端（服务端模式） |
| `send_to_client_by_id`    | `client_id_str`, `message` | `bool` | 向指定客户端 ID 发送消息                 |
| `send_to_server`          | `message: *const c_char`   | `bool` | 客户端向服务器发送消息                   |
| `is_client_connected`     | —                          | `bool` | 查询客户端是否已连接                     |
| `get_server_client_count` | —                          | `u32`  | 获取当前服务端连接数                     |

### 📞 回调设置（关键！）

| 函数                      | 参数                                  | 返回 | 说明                            |
| ------------------------- | ------------------------------------- | ---- | ------------------------------- |
| `set_ws_message_callback` | `callback: Option<fn(*const c_char)>` | `()` | **必须调用！** 设置统一回调函数 |

> 💡 **回调函数原型（易语言需实现）**：
>
> ```c
> void WsMessageCallback(const char* json_data);
> ```
>
> 其中 `json_data` 是 **GBK 编码的 JSON 字符串**，格式如下：

```json
{
  "event_type": "message",        // 或 "connect" / "disconnect"
  "source": "server",             // "server" 表示你是服务端；"client" 表示你是客户端
  "client_id": "123",             // 服务端：客户端ID（数字字符串）；客户端：空字符串 ""
  "message": "Hello World"        // 消息内容（已自动 GBK 解码）
}
```

------

## 🛠️ 三、编译为 Windows DLL（含自动安装编译器）

### 📁 目录结构要求

```text
your_project/
├── Cargo.toml
├── src/
│   └── lib.rs          ← 放入您提供的 lib.rs
└── build.bat           ← 下方提供的批处理脚本
```

### 📄 `Cargo.toml`

```toml
[package]
name = "websocket_epl"
version = "4.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
tokio = { version = "1.0", features = ["full"] }
tokio-tungstenite = "0.21"
tungstenite = "0.21"
futures-util = "0.3"
parking_lot = "0.12"
once_cell = "1.19"
url = "2.5"
aes-gcm = "0.10"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"
encoding_rs = "0.8"
native-tls = "0.2"
tokio-native-tls = "0.3"
libc = "0.2"
chrono = { version = "0.4", features = ["clock"] }
```

### 📜 `build.bat`（智能编译脚本）

```bat
@echo off
setlocal enabledelayedexpansion

:: 获取当前脚本所在目录（支持带空格路径）
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ==================================================
echo     websocket_epl.dll 编译脚本 (v4.1)
echo     工作目录：%CD%
echo ==================================================

:: 检查 Cargo.toml 是否存在
if not exist "Cargo.toml" (
    echo ❌ 错误：未找到 Cargo.toml，请确保在项目根目录运行此脚本。
    pause
    exit /b 1
)

:: 检查 Rust 工具链是否可用
cargo --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Rust 工具链未检测到，正在尝试安装...
    :: 尝试下载并安装 rustup
    where /q curl.exe
    if %errorlevel% neq 0 (
        echo ❌ 错误：系统缺少 curl，无法自动安装 Rust。
        echo 请手动安装 Rust：https://www.rust-lang.org/tools/install
        pause
        exit /b 1
    )
    echo 正在下载 rustup-init.exe...
    curl -sSf -o rustup-init.exe https://win.rustup.rs
    if not exist rustup-init.exe (
        echo ❌ 下载 rustup 失败。
        pause
        exit /b 1
    )
    echo 正在安装 Rust（默认选项）...
    rustup-init.exe -y --default-toolchain stable
    del rustup-init.exe >nul
    echo Rust 安装完成，正在刷新环境变量...
    :: 重新加载 PATH（仅对当前会话有效）
    call "%USERPROFILE%\.cargo\env.bat" 2>nul
    set PATH=%PATH%;%USERPROFILE%\.cargo\bin
)

:: 再次验证 cargo
cargo --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 即使安装后仍无法找到 cargo，请重启命令行或手动配置 PATH。
    pause
    exit /b 1
)

:: 用户选择架构
set /p arch="请选择目标架构 (输入 x86 或 x64，默认 x64): "
if /i "!arch!"=="x86" (
    set "TARGET=i686-pc-windows-msvc"
    set "ARCH_NAME=x86"
) else (
    set "TARGET=x86_64-pc-windows-msvc"
    set "ARCH_NAME=x64"
)

echo.
echo 正在检查目标工具链：!TARGET!

:: 检查是否已安装该 target
rustup target list --installed | findstr /r /c:"^!TARGET!$" >nul
if %errorlevel% neq 0 (
    echo 工具链 !TARGET! 未安装，正在安装...
    rustup target add !TARGET!
    if %errorlevel% neq 0 (
        echo ❌ 安装 !TARGET! 失败。
        pause
        exit /b 1
    )
)

:: 清理旧 DLL（可选）
if exist "websocket_epl.dll" del "websocket_epl.dll"

:: 开始编译
echo.
echo 正在编译 !ARCH_NAME! Release 版本...
echo --------------------------------------------------
cargo build --target !TARGET! --release
if %errorlevel% neq 0 (
    echo.
    echo ❌ 编译失败！请检查代码和依赖。
    pause
    exit /b 1
)

:: 定位生成的 DLL
set "DLL_SRC=target\!TARGET!\release\websocket_epl.dll"
if not exist "!DLL_SRC!" (
    echo ❌ 未找到生成的 DLL：!DLL_SRC!
    pause
    exit /b 1
)

:: 复制到当前目录并重命名
copy "!DLL_SRC!" "websocket_epl.dll" /Y >nul
if %errorlevel% neq 0 (
    echo ❌ 无法复制 DLL 到当前目录。
    pause
    exit /b 1
)

echo.
echo ✅ 成功！已生成：
echo     websocket_epl.dll （!ARCH_NAME! 版本）
echo.
echo 💡 提示：将此 DLL 放入您的易语言工程目录即可调用。
pause
```

> ✅ **使用方式**：
>
> 1. 双击运行 `build.bat`
> 2. 输入 `x86` 或 `x64`
> 3. 脚本会自动安装所需工具链并生成 `websocket_epl.dll`

------

## 💻 四、易语言调用示例

### 1. 完整 DLL 声明（复制到易语言“DLL命令集”中）

```epl
.DLL命令 set_max_clients, , "websocket_epl.dll", "set_max_clients", 设置服务端最大并发连接数
    .参数 limit, 长整数型

.DLL命令 get_max_clients, 长整数型, "websocket_epl.dll", "get_max_clients", 获取当前最大连接数

.DLL命令 set_heartbeat_interval, , "websocket_epl.dll", "set_heartbeat_interval", 设置心跳保活间隔（秒）
    .参数 seconds, 长整数型

.DLL命令 get_heartbeat_interval, 长整数型, "websocket_epl.dll", "get_heartbeat_interval", 获取当前心跳间隔（秒）

.DLL命令 set_read_timeout, , "websocket_epl.dll", "set_read_timeout", 设置读超时时间（秒）
    .参数 seconds, 长整数型

.DLL命令 get_read_timeout, 长整数型, "websocket_epl.dll", "get_read_timeout", 获取当前读超时时间（秒）

.DLL命令 set_replay_window, , "websocket_epl.dll", "set_replay_window", 设置防重放攻击时间窗口（±秒）
    .参数 seconds, 长整数型

.DLL命令 get_replay_window, 长整数型, "websocket_epl.dll", "get_replay_window", 获取当前防重放窗口大小（秒）

.DLL命令 set_log_level, , "websocket_epl.dll", "set_log_level", 设置日志输出级别（0=Error,1=Warn,2=Info,3=Debug）
    .参数 level, 整数型

.DLL命令 set_log_file_path, 逻辑型, "websocket_epl.dll", "set_log_file_path", 设置日志文件路径（GBK）
    .参数 path, 文本型

.DLL命令 write_log, 逻辑型, "websocket_epl.dll", "write_log", 写出日志信息（GBK）
    .参数 level, 整数型, , "0=Error, 1=Warn, 2=Info"
    .参数 message, 文本型

.DLL命令 set_ws_message_callback, , "websocket_epl.dll", "set_ws_message_callback", 设置统一回调函数（JSON格式）
    .参数 callback, 子程序指针

.DLL命令 set_server_encryption_key, 逻辑型, "websocket_epl.dll", "set_server_encryption_key", 设置服务端AES-256密钥（32字节）
    .参数 key, 字节集

.DLL命令 set_client_encryption_key, 逻辑型, "websocket_epl.dll", "set_client_encryption_key", 设置客户端AES-256密钥（32字节）
    .参数 key, 字节集

.DLL命令 enable_encryption, , "websocket_epl.dll", "enable_encryption", 启用/禁用端到端加密
    .参数 enable, 逻辑型

.DLL命令 is_encryption_enabled, 逻辑型, "websocket_epl.dll", "is_encryption_enabled", 查询是否启用加密

.DLL命令 set_skip_cert_verify, , "websocket_epl.dll", "set_skip_cert_verify", 是否跳过TLS证书验证（仅测试用！）
    .参数 skip, 逻辑型

.DLL命令 start_ws_server, 逻辑型, "websocket_epl.dll", "start_ws_server", 启动WebSocket服务端
    .参数 bind_addr, 文本型
    .参数 use_wss, 逻辑型
    .参数 cert_pem_path, 文本型
    .参数 key_pem_path, 文本型

.DLL命令 connect_ws_client, 逻辑型, "websocket_epl.dll", "connect_ws_client", 连接WebSocket服务器（支持自动重连）
    .参数 server_url, 文本型
    .参数 enable_reconnect, 逻辑型

.DLL命令 broadcast_to_clients, 逻辑型, "websocket_epl.dll", "broadcast_to_clients", 广播消息给所有客户端（服务端模式）

.DLL命令 send_to_client_by_id, 逻辑型, "websocket_epl.dll", "send_to_client_by_id", 向指定客户端ID发送消息（服务端模式）
    .参数 client_id_str, 文本型
    .参数 message, 文本型

.DLL命令 send_to_server, 逻辑型, "websocket_epl.dll", "send_to_server", 客户端向服务器发送消息
    .参数 message, 文本型

.DLL命令 is_client_connected, 逻辑型, "websocket_epl.dll", "is_client_connected", 查询客户端是否已连接

.DLL命令 get_server_client_count, 整数型, "websocket_epl.dll", "get_server_client_count", 获取当前服务端连接数

.DLL命令 encrypt_message, 文本型, "websocket_epl.dll", "encrypt_message", 手动加密文本（返回Base64密文）
    .参数 message, 文本型

.DLL命令 decrypt_message, 文本型, "websocket_epl.dll", "decrypt_message", 手动解密Base64密文（返回明文）
    .参数 encrypted_message, 文本型
```

### 2. 实现回调子程序（JSON 解析）

```epl
.子程序 WebSocket回调, , 公开
.参数 json_data, 文本型

.局部变量 json, 类_json
.局部变量 event_type, 文本型
.局部变量 source, 文本型
.局部变量 client_id, 文本型
.局部变量 message, 文本型

json.解析 (json_data)
event_type ＝ json.取通用属性 (“event_type”, )
source ＝ json.取通用属性 (“source”, )
client_id ＝ json.取通用属性 (“client_id”, )
message ＝ json.取通用属性 (“message”, )

.判断开始 (event_type ＝ “connect”)
    信息框 (“连接事件：” ＋ source ＋ “ 已连接”, 0, )
.判断分支 (event_type ＝ “disconnect”)
    信息框 (“断开事件：” ＋ source ＋ “ 已断开”, 0, )
.判断分支 (event_type ＝ “message”)
    .如果真 (source ＝ “server”)
        信息框 (“收到来自客户端 [” ＋ client_id ＋ “] 的消息：” ＋ message, 0, )
    .否则
        信息框 (“收到服务器消息：” ＋ message, 0, )
    .如果真结束
.默认
    调试输出 (“未知事件类型：” ＋ event_type)
.判断结束
```

### 3. 启动服务端

```epl
set_ws_message_callback (&WebSocket回调)
.如果真 (start_ws_server (“0.0.0.0:8765”, 假, “”, “”))
    信息框 (“服务端启动成功！”, 0, )
.否则
    信息框 (“服务端启动失败！”, 0, )
.如果真结束
```

### 4. 客户端连接 + 加密

```epl
.局部变量 key, 字节集
key ＝ 到字节集 (“12345678901234567890123456789012”) ' 32字节

set_client_encryption_key (key)
enable_encryption (真)

.如果真 (connect_ws_client (“ws://127.0.0.1:8765”, 真))
    send_to_server (“Hello from EPL!”)
.否则
    信息框 (“连接失败”, 0, )
.如果真结束
```

------

## ⚠️ 五、重要注意事项

1. **必须先调用 `set_ws_message_callback`**，否则无法接收任何消息。
2. **字符串编码**：易语言默认 GBK，与 DLL 完全兼容，无需转换。
3. **WSS 证书**：必须提供 PEM 格式的 `.crt`（或 `.pem`）和 `.key` 文件。
4. **生产环境安全**：
   - 务必调用 `set_skip_cert_verify(false)`（默认已是 false）
   - 不要硬编码密钥，应从配置文件或用户输入读取
5. **内存管理**：
   - `encrypt_message` / `decrypt_message` 返回的字符串由 Rust 分配
   - **在 Windows MSVC 环境下，易语言可安全使用，无需手动释放**
   - 长期运行建议监控内存，如有泄漏可考虑升级 DLL 版本（未来可能导出 `free_c_string`）
6. **日志调试**：开发阶段建议开启 Debug 日志：`set_log_level(3)`

------

## 🧪 六、推荐测试流程

1. 先用 `ws://` 测试基本通信（不加密）
2. 启用 `enable_encryption(true)` + 设置相同密钥，测试加密通信
3. 部署 `wss://` 并确保 `set_skip_cert_verify(false)`
4. 使用 `set_log_file_path("ws.log")` 记录运行日志

------

> 📌 **最终输出文件**：`websocket_epl.dll`
>  支持 Windows 7+，需安装 Microsoft Visual C++ Redistributable（x86/x64 对应版本）

------

如有问题，可通过日志定位：查看控制台输出或指定的日志文件。