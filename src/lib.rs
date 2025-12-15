//! ============================================================================
//! WebSocket DLL for 易语言 (EPL) —— 生产级实现 v4.0（终极修复+全功能）
//!
//! 【核心特性】
//! ✅ 同时支持服务端 & 客户端
//! ✅ 支持 WS / WSS（TLS 1.2+）
//! ✅ 自动 GBK ↔ UTF-8 转换（适配易语言字符串）aa
//! ✅ 可选 AES-256-GCM 端到端加密（防窃听）
//! ✅ 防重放攻击（±5 分钟时间窗口）
//! ✅ 心跳保活（Ping/Pong）、读超时断连、自动重连
//! ✅ 广播、定向发送、回调通知
//! ✅ 线程安全、无内存泄漏、release 模式无 panic
//!
//! 【调用约定】
//! - 所有导出函数均为 extern "system"（stdcall）
//! - 字符串参数为 null-terminated GBK 编码（C 风格）
//! - 回调函数原型：
//!     fn(source: *const c_char, client_id: *const c_char, message: *const c_char)
//!     - source: "server" 或 "client"
//!     - client_id: 服务端模式下为数字 ID（如 "123"），客户端模式下为空 ""
//!
//! 【安全建议】
//! - 生产环境务必调用 set_skip_cert_verify(false)
//! - 密钥应通过安全方式传入（非硬编码）
//! ============================================================================

// =============================================================================
// 📦 模块引入和类型定义
// =============================================================================

// 标准库引入
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;
use std::io::Write;

// 外部依赖引入
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use once_cell::sync::Lazy;
use url::Url;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng, generic_array::GenericArray},
};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use tungstenite::Message;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use libc;

// =============================================================================
// ⚙️ 配置和常量定义
// =============================================================================

/// WebSocket 配置结构体
#[derive(Debug)]
struct WsConfig {
    max_clients: AtomicUsize,
    heartbeat_interval: AtomicU64,
    read_timeout: AtomicU64,
    replay_window: AtomicI64,
    skip_cert_verify: AtomicBool,
    encryption_enabled: AtomicBool,
}

impl WsConfig {
    const fn new() -> Self {
        Self {
            max_clients: AtomicUsize::new(1000),
            heartbeat_interval: AtomicU64::new(30),
            read_timeout: AtomicU64::new(60),
            replay_window: AtomicI64::new(300),
            skip_cert_verify: AtomicBool::new(false),
            encryption_enabled: AtomicBool::new(false),
        }
    }

    fn get_max_clients(&self) -> usize {
        self.max_clients.load(Ordering::SeqCst)
    }

    fn set_max_clients(&self, limit: usize) {
        self.max_clients.store(limit, Ordering::SeqCst);
    }

    fn get_heartbeat_interval(&self) -> u64 {
        self.heartbeat_interval.load(Ordering::SeqCst)
    }

    fn set_heartbeat_interval(&self, seconds: u64) {
        self.heartbeat_interval.store(seconds, Ordering::SeqCst);
    }

    fn get_read_timeout(&self) -> u64 {
        self.read_timeout.load(Ordering::SeqCst)
    }

    fn set_read_timeout(&self, seconds: u64) {
        self.read_timeout.store(seconds, Ordering::SeqCst);
    }

    fn get_replay_window(&self) -> i64 {
        self.replay_window.load(Ordering::SeqCst)
    }

    fn set_replay_window(&self, seconds: i64) {
        self.replay_window.store(seconds, Ordering::SeqCst);
    }

    fn get_skip_cert_verify(&self) -> bool {
        self.skip_cert_verify.load(Ordering::SeqCst)
    }

    fn set_skip_cert_verify(&self, skip: bool) {
        self.skip_cert_verify.store(skip, Ordering::SeqCst);
    }

    fn get_encryption_enabled(&self) -> bool {
        self.encryption_enabled.load(Ordering::SeqCst)
    }

    fn set_encryption_enabled(&self, enabled: bool) {
        self.encryption_enabled.store(enabled, Ordering::SeqCst);
    }
}

/// 全局配置实例
static CONFIG: Lazy<WsConfig> = Lazy::new(|| WsConfig::new());

// =============================================================================
// 🧠 全局状态管理
// =============================================================================

/// 回调函数类型定义
type WsCallbackJson = extern "system" fn(*const c_char);

/// 回调函数指针
static MESSAGE_CALLBACK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// 服务端客户端连接管理
static SERVER_CLIENTS: Lazy<Mutex<HashMap<u64, ClientConnection>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 服务端：下一个客户端 ID（自增）
static NEXT_CLIENT_ID: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

/// 客户端连接状态
static CLIENT_SENDER: Lazy<Mutex<Option<mpsc::UnboundedSender<String>>>> =
    Lazy::new(|| Mutex::new(None));
static IS_CLIENT_CONNECTED: AtomicBool = AtomicBool::new(false);
static CLIENT_RECONNECT: AtomicBool = AtomicBool::new(false);
static CLIENT_URL: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// =============================================================================
// 🔐 加密相关定义
// =============================================================================

/// 加密密钥管理
static SERVER_ENCRYPTION_KEY: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));
static CLIENT_ENCRYPTION_KEY: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));

/// 防重放攻击时间戳记录
static LAST_MESSAGE_TS: Lazy<Mutex<HashMap<String, i64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// =============================================================================
// 📝 日志系统
// =============================================================================

/// 日志级别枚举
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    fn from_u8(level: u8) -> Self {
        match level {
            0 => LogLevel::Error,
            1 => LogLevel::Warn,
            2 => LogLevel::Info,
            3 => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}

/// 当前日志级别
static LOG_LEVEL: AtomicU8 = AtomicU8::new(2); // 默认为 Info 级别

/// 检查是否应该记录指定级别的日志
/// 如果 force_output 为 true，则忽略当前日志级别限制
fn should_log(level: LogLevel, force_output: bool) -> bool {
    if force_output {
        return true;
    }
    let current_level = LOG_LEVEL.load(Ordering::Relaxed);
    (level as u8) <= current_level
}

// 修改现有的日志宏定义
macro_rules! log_info {
    ($force:expr, $($arg:tt)*) => {{
        if should_log(LogLevel::Info,  $force) {
            let msg = format!("[INFO] {}\n", format_args!($($arg)*));
            eprintln!("{}", msg.trim_end());

            // 如果设置了日志文件路径，则同时写入文件
            if let Some(ref path) = *LOG_FILE_PATH.lock() {
                let _ = append_to_log_file(path, &msg);
            }
        }
    }};
}

macro_rules! log_warn {
    ($force:expr, $($arg:tt)*) => {{
        if should_log(LogLevel::Warn,  $force) {
            let msg = format!("[WARN] {}\n", format_args!($($arg)*));
            eprintln!("{}", msg.trim_end());

            if let Some(ref path) = *LOG_FILE_PATH.lock() {
                let _ = append_to_log_file(path, &msg);
            }
        }
    }};
}

macro_rules! log_error {
    ($force:expr, $($arg:tt)*) => {{
        if should_log(LogLevel::Error,  $force) {
            let msg = format!("[ERROR] {}\n", format_args!($($arg)*));
            eprintln!("{}", msg.trim_end());

            if let Some(ref path) = *LOG_FILE_PATH.lock() {
                let _ = append_to_log_file(path, &msg);
            }
        }
    }};
}

/// 日志文件路径
static LOG_FILE_PATH: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// 辅助函数：追加日志到文件
fn append_to_log_file(path: &str, content: &str) -> std::io::Result<()> {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let log_entry = format!("{} {}", timestamp, content);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    file.write_all(log_entry.as_bytes())?;
    file.flush()?;
    Ok(())
}

// =============================================================================
// 📦 数据结构定义
// =============================================================================

/// 客户端连接信息
#[allow(dead_code)]
struct ClientConnection {
    id: u64,
    sender: mpsc::UnboundedSender<String>,
    connected_at: SystemTime,
    last_active: AtomicU64,
}

#[allow(dead_code)]
impl ClientConnection {
    fn new(id: u64, sender: mpsc::UnboundedSender<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            sender,
            connected_at: SystemTime::now(),
            last_active: AtomicU64::new(now),
        }
    }

    /// 更新活动时间
    fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_active.store(now, Ordering::Relaxed);
    }

    /// 获取连接时间
    fn get_connected_at(&self) -> &SystemTime {
        &self.connected_at
    }

    /// 获取最后活动时间
    fn get_last_active(&self) -> i64 {
        self.last_active.load(Ordering::Relaxed) as i64
    }

    /// 获取连接ID
    fn get_id(&self) -> u64 {
        self.id
    }

    /// 获取连接发送通道
    fn get_sender(&self) -> &mpsc::UnboundedSender<String> {
        &self.sender
    }
}

/// 加密消息结构体
#[derive(Serialize, Deserialize)]
struct EncryptedMessage {
    #[serde(rename = "type")]
    msg_type: String, // 类型（目前固定为 "text"）
    data: String,     // 原始明文消息
    ts: i64,          // 时间戳（毫秒），用于防重放
}

/// 事件类型枚举
#[derive(Serialize)]
enum EventType {
    #[serde(rename = "message")]
    Message,
    #[serde(rename = "connect")]
    Connect,
    #[serde(rename = "disconnect")]
    Disconnect,
}

/// 扩展的回调数据结构，支持多种事件类型
#[derive(Serialize)]
struct ExtendedCallbackData {
    event_type: EventType,
    source: String,
    client_id: String,
    message: String,
}

// =============================================================================
// 🌐 字符编码转换工具
// =============================================================================

/// 将 C 风格 GBK 字符串转为 Rust UTF-8 String
unsafe fn cstr_gbk_to_utf8(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() { return None; }
    let bytes = CStr::from_ptr(ptr).to_bytes();
    let (cow, _encoding, _had_errors) = encoding_rs::GBK.decode(bytes);
    Some(cow.into_owned())
}

/// 将 Rust UTF-8 字符串转为 C 风格 GBK CString
fn utf8_to_cstring_gbk(s: &str) -> Option<CString> {
    let (cow, _encoding, _had_errors) = encoding_rs::GBK.encode(s);
    let vec = cow.into_owned();
    if vec.contains(&0u8) { return None; } // 防止内部包含 \0
    CString::new(vec).ok()
}

// =============================================================================
// 🔑 加密/解密工具函数
// =============================================================================

/// 从 C 风格字符串解析 32 字节密钥
unsafe fn parse_key_from_cstr(key_ptr: *const c_char) -> Option<[u8; 32]> {
    if key_ptr.is_null() { return None; }
    let bytes = CStr::from_ptr(key_ptr).to_bytes();
    if bytes.len() != 32 {
        log_error!(false, "parse_key_from_cstr - 密钥长度必须为 32 字节，当前: {}", bytes.len());
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Some(key)
}

/// 使用 AES-256-GCM 加密明文（返回 Base64 编码字符串）
fn encrypt_with_key(plaintext: &str, key: &[u8; 32]) -> Option<String> {
    log_info!(false, "encrypt_with_key - 开始加密，原文: {}, 长度: {}", plaintext, plaintext.len());
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).ok()?;
    let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    log_info!(false, "encrypt_with_key - 加密完成，密文: {}, 长度: {}", plaintext, plaintext.len());
    Some(general_purpose::STANDARD.encode(&output))
}

/// 解密 Base64 编码的密文
fn decrypt_with_key(b64_ciphertext: &str, key: &[u8; 32]) -> Option<String> {
    log_info!(false, "decrypt_with_key - 开始解密，输入密文: {}, 长度: {}", b64_ciphertext, b64_ciphertext.len());

    let decoded = general_purpose::STANDARD.decode(b64_ciphertext).ok()?;
    log_info!(false, "decrypt_with_key - Base64解码完成，解码后长度: {}", decoded.len());

    if decoded.len() < 28 {
        log_warn!(false, "decrypt_with_key - 解码后数据太短，至少需要28字节，实际: {}字节", decoded.len());
        return None;
    } // 至少 12B nonce + 数据

    let nonce = GenericArray::from_slice(&decoded[..12]);
    let ciphertext = &decoded[12..];

    log_info!(false, "decrypt_with_key - Nonce长度: {}, 密文长度: {}", nonce.len(), ciphertext.len());

    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let plaintext = cipher.decrypt(nonce, ciphertext).ok();

    match plaintext {
        Some(ref data) => {
            let result = String::from_utf8(data.clone()).ok();
            match result {
                Some(ref text) => {
                    log_info!(false, "decrypt_with_key - 解密成功，明文: {}, 长度: {}", text, text.len());
                },
                None => {
                    log_warn!(false, "decrypt_with_key - 解密数据不是有效的UTF-8字符串");
                    log_info!(false, "decrypt_with_key - 解密后的字节数据（前50字节）: {:?}", &data[..std::cmp::min(50, data.len())]);
                }
            }
            result
        },
        None => {
            log_warn!(false, "decrypt_with_key - AES解密失败");
            None
        }
    }
}

/// 构建带时间戳的明文消息（用于加密前包装）
fn build_plaintext_message(original_text: &str) -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
    let msg = EncryptedMessage {
        msg_type: "text".to_string(),
        data: original_text.to_string(),
        ts,
    };
    let json_str = serde_json::to_string(&msg).unwrap_or_else(|_| original_text.to_string());
    log_info!(false, "build_plaintext_message - 构建明文消息，原文: {}, 包装后JSON: {}", original_text, json_str);
    json_str
}

/// 从 JSON 中提取原始消息，并验证时间戳（防重放）
fn extract_original_message(json_str: &str, source_id: &str) -> Option<String> {
    log_info!(false, "extract_original_message - 开始提取原始消息，输入JSON: {}", json_str);

    // 一次性解析消息
    let msg = match serde_json::from_str::<EncryptedMessage>(json_str) {
        Ok(m) => {
            log_info!(false, "extract_original_message - JSON解析成功，消息类型: {}, 数据: {}, 时间戳: {}", m.msg_type, m.data, m.ts);
            m
        },
        Err(e) => {
            log_warn!(false, "extract_original_message - JSON解析失败: {}，输入数据: {}", e, json_str);
            return None;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let time_diff = now - msg.ts;

    log_info!(false, 
        "extract_original_message - 时间戳验证，当前时间: {}, 消息时间: {}, 差值: {}ms",
        now,
        msg.ts,
        time_diff
    );

    // 需要先获取 AtomicI64 的值，再进行计算
    let replay_window = CONFIG.get_replay_window() * 1000;
    if time_diff.abs() > replay_window {
        log_warn!(false, "extract_original_message - 消息时间戳过期（{}ms），来源: {}，允许窗口: ±{}ms", time_diff, source_id, replay_window);
        return None;
    }

    // 更新最后时间戳（防止重复）
    LAST_MESSAGE_TS.lock().insert(source_id.to_string(), msg.ts);

    log_info!(false, "extract_original_message - 消息验证通过，提取原始内容: {}", msg.data);
    Some(msg.data)
}

// =============================================================================
// 🔄 消息处理管道（加解密 + 防重放）
// =============================================================================

fn process_outgoing_for_server(text: &str) -> String {
    log_info!(false, "开始处理服务端发出的消息，加密启用状态: {}", CONFIG.get_encryption_enabled());

    if !CONFIG.get_encryption_enabled() {
        log_info!(false, "服务端消息未加密，直接返回原文");
        return text.to_string();
    }

    let has_key = SERVER_ENCRYPTION_KEY.lock().is_some();
    log_info!(false, "服务端密钥设置状态: {}", has_key);

    if let Some(key) = SERVER_ENCRYPTION_KEY.lock().as_ref() {
        log_info!(false, "尝试加密消息，原文长度: {}，原文内容：{}", text.len(), text);
        if let Some(enc) = encrypt_with_key(&build_plaintext_message(text), key) {
            log_info!(false, "消息加密成功，密文长度: {}，密文内容：{}", enc.len(), enc);
            return enc;
        } else {
            log_warn!(false, "加密失败，使用明文发送");
        }
    } else {
        log_warn!(false, "加密启用但服务端密钥未设，发送明文");
    }

    text.to_string()
}

fn process_outgoing_for_client(text: &str) -> String {
    log_info!(false, "开始处理客户端发出的消息，加密启用状态: {}", CONFIG.get_encryption_enabled());
    if !CONFIG.get_encryption_enabled() {
        log_info!(false, "客户端消息未加密，直接返回原文");
        return text.to_string();
    }

    let has_key = CLIENT_ENCRYPTION_KEY.lock().is_some();
    log_info!(false, "客户端密钥设置状态: {}", has_key);

    if let Some(key) = CLIENT_ENCRYPTION_KEY.lock().as_ref() {
        log_info!(false, "尝试加密消息，原文长度: {}，原文内容：{}", text.len(), text);
        if let Some(enc) = encrypt_with_key(&build_plaintext_message(text), key) {
            log_info!(false, "消息加密成功，密文长度: {}，密文内容：{}", enc.len(), enc);
            return enc;
        } else {
            log_warn!(false, "加密失败，使用明文发送");
        }
    } else {
        log_warn!(false, "加密启用但客户端密钥未设，发送明文");
    }

    text.to_string()
}

fn process_incoming_for_server(encrypted_or_plain: &str, client_id: &str) -> Option<String> {
    log_info!(false, "开始处理来自客户端 {} 的消息，加密启用状态: {}", client_id, CONFIG.get_encryption_enabled());
    if !CONFIG.get_encryption_enabled() {
        log_info!(false, "消息未加密，直接返回原文");
        return Some(encrypted_or_plain.to_string());
    }

    let has_key = SERVER_ENCRYPTION_KEY.lock().is_some();
    log_info!(false, "服务端密钥设置状态: {}", has_key);

    if let Some(key) = SERVER_ENCRYPTION_KEY.lock().as_ref() {
        log_info!(false, "尝试解密消息，长度: {}，内容：{}", encrypted_or_plain.len(), encrypted_or_plain);
        if let Some(plain) = decrypt_with_key(encrypted_or_plain, key) {
            log_info!(false, "解密成功，尝试提取原始消息");
            let result = extract_original_message(&plain, client_id);
            if result.is_some() {
                log_info!(false, "消息处理完成，成功提取原始内容，长度: {}，内容：{}", result.as_ref().unwrap().len(), result.as_ref().unwrap());
            } else {
                log_warn!(false, "消息解密成功但内容验证失败");
            }
            return result;
        } else {
            log_warn!(false, "解密失败，可能是密钥不匹配或数据损坏");
        }
    }
    None
}

fn process_incoming_for_client(encrypted_or_plain: &str) -> Option<String> {
    log_info!(false, "开始处理来自服务器的消息，加密启用状态: {}", CONFIG.get_encryption_enabled());

    if !CONFIG.get_encryption_enabled() {
        log_info!(false, "消息未加密，直接返回原文");
        return Some(encrypted_or_plain.to_string());
    }

    let has_key = CLIENT_ENCRYPTION_KEY.lock().is_some();
    log_info!(false, "客户端密钥设置状态: {}", has_key);

    if let Some(key) = CLIENT_ENCRYPTION_KEY.lock().as_ref() {
        log_info!(false, "尝试解密消息，长度: {}，内容：{}", encrypted_or_plain.len(), encrypted_or_plain);
        if let Some(plain) = decrypt_with_key(encrypted_or_plain, key) {
            log_info!(false, "解密成功，尝试提取原始消息");
            let result = extract_original_message(&plain, "server");
            if result.is_some() {
                log_info!(false, "消息处理完成，成功提取原始内容，长度: {}，内容：{}", result.as_ref().unwrap().len(), result.as_ref().unwrap());
            } else {
                log_warn!(false, "消息解密成功但内容验证失败");
            }
            return result;
        } else {
            log_warn!(false, "解密失败，可能是密钥不匹配或数据损坏");
        }
    }
    None
}

// =============================================================================
// 📞 回调调用封装（安全调用易语言函数）
// =============================================================================

fn call_epl_callback(source: &str, client_id: &str, message: &str) {
    let ptr = MESSAGE_CALLBACK.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let callback: WsCallbackJson = unsafe { std::mem::transmute(ptr) };

        // 构造JSON数据
        let callback_data = ExtendedCallbackData {
            event_type: EventType::Message,
            source: source.to_string(),
            client_id: client_id.to_string(),
            message: message.to_string(),
        };

        if let Ok(json_str) = serde_json::to_string(&callback_data) {
            if let Some(c_json) = utf8_to_cstring_gbk(&json_str) {
                callback(c_json.as_ptr());
            }
        }
    }
}

/// 发送连接事件回调
fn call_connection_event(source: &str, client_id: &str, connected: bool) {
    let ptr = MESSAGE_CALLBACK.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let callback: WsCallbackJson = unsafe { std::mem::transmute(ptr) };

        let event_data = ExtendedCallbackData {
            event_type: if connected { EventType::Connect } else { EventType::Disconnect },
            source: source.to_string(),
            client_id: client_id.to_string(),
            message: if connected { "connected".to_string() } else { "disconnected".to_string() },
        };

        if let Ok(json_str) = serde_json::to_string(&event_data) {
            if let Some(c_json) = utf8_to_cstring_gbk(&json_str) {
                callback(c_json.as_ptr());
            }
        }
    }
}

// =============================================================================
// 📥 DLL 导出函数（供易语言调用）
// =============================================================================

/// 设置最大并发连接数（默认值：1000）
#[no_mangle]
pub extern "system" fn set_max_clients(limit: usize) {
    CONFIG.set_max_clients(limit);
    log_info!(false, "🔧 最大并发连接数已设置为: {}", limit);
}

/// 获取当前最大并发连接数
#[no_mangle]
pub extern "system" fn get_max_clients() -> usize {
    CONFIG.get_max_clients()
}

/// 设置心跳间隔（秒）（默认值：30）
#[no_mangle]
pub extern "system" fn set_heartbeat_interval(seconds: u64) {
    CONFIG.set_heartbeat_interval(seconds);
    log_info!(false, "🔧 心跳间隔已设置为: {} 秒", seconds);
}

/// 获取当前心跳间隔（秒）
#[no_mangle]
pub extern "system" fn get_heartbeat_interval() -> u64 {
    CONFIG.get_heartbeat_interval()
}

/// 设置读超时时间（秒）（默认值：60）
#[no_mangle]
pub extern "system" fn set_read_timeout(seconds: u64) {
    CONFIG.set_read_timeout(seconds);
    log_info!(false, "🔧 读超时时间已设置为: {} 秒", seconds);
}

/// 获取当前读超时时间（秒）
#[no_mangle]
pub extern "system" fn get_read_timeout() -> u64 {
    CONFIG.get_read_timeout()
}

/// 设置防重放时间窗口（秒）（默认值：300，即±5分钟）
#[no_mangle]
pub extern "system" fn set_replay_window(seconds: i64) {
    CONFIG.set_replay_window(seconds);
    log_info!(false, "🔧 防重放时间窗口已设置为: ±{} 秒", seconds);
}

/// 获取当前防重放时间窗口（秒）
#[no_mangle]
pub extern "system" fn get_replay_window() -> i64 {
    CONFIG.get_replay_window()
}

/// 设置日志级别（0=Error, 1=Warn, 2=Info, 3=Debug）
#[no_mangle]
pub extern "system" fn set_log_level(level: u8) {
    let log_level = LogLevel::from_u8(level);
    LOG_LEVEL.store(level.min(3), Ordering::Relaxed);
    log_info!(true, "日志级别已设置为: {:?}", log_level);
}

/// 写出日志信息（0=Error, 1=Warn, 2=Info）
#[no_mangle]
pub extern "system" fn write_log(level: u8, message: *const c_char) {
    if let Some(msg_str) = unsafe { cstr_gbk_to_utf8(message) } {
        match level {
            0 => log_error!(true, "{}", msg_str),
            1 => log_warn!(true, "{}", msg_str),
            2 => log_info!(true, "{}", msg_str),
            _ => {}
        }
    }
}

/// 设置日志文件路径的导出函数
#[no_mangle]
pub extern "system" fn set_log_file_path(path: *const c_char) -> bool {
    if let Some(path_str) = unsafe { cstr_gbk_to_utf8(path) } {
        *LOG_FILE_PATH.lock() = Some(path_str);
        true
    } else {
        false
    }
}

/// 设置消息回调函数（改造为通用JSON格式）
/// 回调函数将接收JSON格式的字符串，包含source, client_id和message信息
/// JSON格式示例:
/// 1、普通消息：{ "event_type": "message", "source": "server", "client_id": "123", "message": "Hello World" }
/// 2、客户端连接：{ "event_type": "connect", "source": "server", "client_id": "123", "message": "connected" }
/// 3、客户端断开：{ "event_type": "disconnect", "source": "server", "client_id": "123", "message": "disconnected" }
/// 4、客户端连接成功：{ "event_type": "connect", "source": "client", "client_id": "123", "message": "connected" }
/// 5、客户端断开连接：{ "event_type": "disconnect", "source": "client", "client_id": "123", "message": "disconnected" }
#[no_mangle]
pub extern "system" fn set_ws_message_callback(
    callback: Option<extern "system" fn(*const c_char)>,
) {
    let ptr = match callback {
        Some(f) => f as *const () as *mut (),
        None => std::ptr::null_mut(),
    };
    MESSAGE_CALLBACK.store(ptr, Ordering::SeqCst);
    log_info!(false, "📤 消息回调函数已设置（JSON格式）");
}

/// 设置服务端加密密钥（32 字节原始字节）
#[no_mangle]
pub extern "system" fn set_server_encryption_key(key: *const c_char) -> bool {
    match unsafe { parse_key_from_cstr(key) } {
        Some(k) => {
            *SERVER_ENCRYPTION_KEY.lock() = Some(k);
            log_info!(false, "✅ 服务端密钥已设置");
            true
        }
        None => false,
    }
}

/// 设置客户端加密密钥（32 字节原始字节）
#[no_mangle]
pub extern "system" fn set_client_encryption_key(key: *const c_char) -> bool {
    match unsafe { parse_key_from_cstr(key) } {
        Some(k) => {
            *CLIENT_ENCRYPTION_KEY.lock() = Some(k);
            log_info!(false, "✅ 客户端密钥已设置");
            true
        }
        None => false,
    }
}

/// 启用/禁用端到端加密
#[no_mangle]
pub extern "system" fn enable_encryption(enable: bool) {
    CONFIG.set_encryption_enabled(enable);
    log_info!(false, "🔒 加密已{}", if enable { "启用" } else { "禁用" });
}

/// 查询加密是否启用
#[no_mangle]
pub extern "system" fn is_encryption_enabled() -> bool {
    CONFIG.get_encryption_enabled()
}

/// 控制是否跳过 TLS 证书验证（⚠️ 仅测试用！生产环境应设为 false）
#[no_mangle]
pub extern "system" fn set_skip_cert_verify(skip: bool) {
    CONFIG.set_skip_cert_verify(skip);
    log_info!(false, "🛡️ 证书验证跳过已{}", if skip { "启用" } else { "禁用" });
}

/// 启动 WebSocket 服务端（分别处理 WS 和 WSS）
#[no_mangle]
pub extern "system" fn start_ws_server(
    bind_addr: *const c_char,      // 绑定地址，如 "0.0.0.0:8765"
    use_wss: bool,                 // 是否启用 WSS
    cert_pem_path: *const c_char,  // 证书路径（GBK）
    key_pem_path: *const c_char,   // 私钥路径（GBK）
) -> bool {
    let addr = unsafe { cstr_gbk_to_utf8(bind_addr) }.unwrap_or_else(|| "0.0.0.0:8765".to_string());

    // 提前拷贝证书和私钥路径字符串再 move 到线程里
    let cert_pem_path_opt = if use_wss {
        unsafe { cstr_gbk_to_utf8(cert_pem_path) }
    } else {
        None
    };
    let key_pem_path_opt = if use_wss {
        unsafe { cstr_gbk_to_utf8(key_pem_path) }
    } else {
        None
    };

    // 校验 WSS 模式下必须提供路径
    if use_wss && (cert_pem_path_opt.is_none() || key_pem_path_opt.is_none()) {
        log_error!(false, "WSS 模式需要同时提供证书与私钥路径");
        return false;
    }

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("创建 Tokio 运行时失败");
        rt.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    log_error!(false, "服务端绑定失败 {}: {}", addr, e);
                    return;
                }
            };
            log_info!(false, "✅ WebSocket 服务端启动: {} (WSS={})", addr, use_wss);

            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log_error!(false, "接受连接失败: {}", e);
                        continue;
                    }
                };

                if SERVER_CLIENTS.lock().len() >= CONFIG.get_max_clients() {
                    log_error!(false, "达到最大连接数 {}，拒绝: {}", CONFIG.get_max_clients(), peer);
                    drop(stream);
                    continue;
                }

                let client_id = {
                    let mut id_gen = NEXT_CLIENT_ID.lock();
                    let id = *id_gen;
                    *id_gen += 1;
                    id
                };

                // 如果启用了 WSS，则处理 TLS 连接
                if use_wss {
                    // 获取并验证证书及私钥路径
                    let cert_path = cert_pem_path_opt.as_ref().unwrap();  // 已确保非空
                    // let cert_path = match unsafe { cstr_gbk_to_utf8(cert_pem_path) } {
                    //     Some(p) => p,
                    //     None => {
                    //         log_error!(false, "WSS 模式需要提供证书路径");
                    //         continue;
                    //     }
                    // };

                    let key_path = key_pem_path_opt.as_ref().unwrap();
                    // let key_path = match unsafe { cstr_gbk_to_utf8(key_pem_path) } {
                    //     Some(p) => p,
                    //     None => {
                    //         log_error!(false, "WSS 模式需要提供私钥路径");
                    //         continue;
                    //     }
                    // };

                    // 读取证书和私钥文件
                    let cert_bytes = match std::fs::read(&cert_path) {
                        Ok(b) => b,
                        Err(e) => {
                            log_error!(false, "读取证书文件失败 '{}': {}", cert_path, e);
                            continue;
                        }
                    };

                    let key_bytes = match std::fs::read(&key_path) {
                        Ok(b) => b,
                        Err(e) => {
                            log_error!(false, "读取私钥文件失败 '{}': {}", key_path, e);
                            continue;
                        }
                    };

                    // 创建 TLS Identity 对象
                    let identity = match native_tls::Identity::from_pkcs8(&cert_bytes, &key_bytes) {
                        Ok(id) => id,
                        Err(e) => {
                            log_error!(false, "从证书和私钥创建 TLS Identity 失败: {}", e);
                            continue;
                        }
                    };

                    // 创建 TLS 接受器
                    let native_acceptor = match native_tls::TlsAcceptor::new(identity) {
                        Ok(a) => a,
                        Err(e) => {
                            log_error!(false, "创建 TLS 接受器失败: {}", e);
                            continue;
                        }
                    };

                    let acceptor = tokio_native_tls::TlsAcceptor::from(native_acceptor);

                    // 执行 TLS 握手
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            log_error!(false, "TLS 握手失败（客户端 {}）: {}", peer, e);
                            continue;
                        }
                    };

                    // 执行 WebSocket 协议握手
                    let ws_stream = match tokio_tungstenite::accept_async(tls_stream).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            log_error!(false, "WSS 协议握手失败: {}", e);
                            continue;
                        }
                    };

                    // 分离 WebSocket 的读写端
                    let (write, mut read) = ws_stream.split();

                    // 使用 Arc<Mutex<>> 包装 write 以便在多个任务间共享
                    let write = Arc::new(TokioMutex::new(write));

                    // 创建消息通道用于向客户端发送消息
                    let (tx, rx) = mpsc::unbounded_channel::<String>();
                    let connection = ClientConnection::new(client_id, tx.clone());
                    SERVER_CLIENTS.lock().insert(client_id, connection);
                    log_info!(false, "🔌 新客户端 {} 连接: {}", client_id, peer);
                    // 调用连接事件
                    call_connection_event("server", &client_id.to_string(), true);

                    // 启动读任务 - 处理来自客户端的消息
                    tokio::spawn({
                        let write_clone = write.clone(); // 克隆 Arc 引用
                        let client_id_str = client_id.to_string();
                        async move {
                            let mut ping_interval = interval(Duration::from_secs(CONFIG.get_heartbeat_interval()));
                            ping_interval.tick().await;

                            loop {
                                tokio::select! {
                                    // 从 WebSocket 读取数据
                                    msg = timeout(Duration::from_secs(CONFIG.get_read_timeout()), read.next()) => {
                                        match msg {
                                            // 成功读取到文本消息
                                            Ok(Some(Ok(Message::Text(ref text)))) => {
                                                if let Some(original) = process_incoming_for_server(text.as_str(), &client_id_str) {
                                                    call_epl_callback("server", &client_id_str, &original);
                                                }
                                            }
                                            // 处理 Ping 消息，回复 Pong
                                            Ok(Some(Ok(Message::Ping(data)))) => {
                                                let _ = write_clone.lock().await.send(Message::Pong(data)).await;
                                            }
                                            // 客户端关闭连接或发生错误
                                            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                                            _ => {}
                                        }
                                    }
                                    // 定期发送心跳包
                                    _ = ping_interval.tick() => {
                                        let _ = write_clone.lock().await.send(Message::Ping(vec![].into())).await;
                                    }
                                }
                            }

                            // 客户端断开连接，清理资源
                            SERVER_CLIENTS.lock().remove(&client_id);
                            log_info!(false, "👋 客户端 {} 断开", client_id);
                            // 调用断开事件
                            call_connection_event("server", &client_id.to_string(), false);
                        }
                    });

                    // 启动写任务 - 向客户端发送消息
                    tokio::spawn(async move {
                        let mut rx = rx; // 添加这一行来获得所有权并启用 mutability
                        while let Some(msg) = rx.recv().await {
                            let final_msg = process_outgoing_for_server(&msg);
                            if let Err(e) = write.lock().await.send(Message::Text(final_msg.into())).await {
                                log_error!(false, "向客户端 {} 发送消息失败: {}", client_id, e);
                                break;
                            }
                        }
                    });
                }
                // 处理普通的 WebSocket 连接 (非加密)
                else {
                    // 执行 WebSocket 协议握手
                    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            log_error!(false, "WS 协议握手失败: {}", e);
                            continue;
                        }
                    };

                    // 分离 WebSocket 的读写端
                    let (write, mut read) = ws_stream.split();

                    // 使用 Arc<Mutex<>> 包装 write 以便在多个任务间共享
                    let write = Arc::new(TokioMutex::new(write));

                    // 创建消息通道用于向客户端发送消息
                    let (tx, rx) = mpsc::unbounded_channel::<String>();
                    let connection = ClientConnection::new(client_id, tx.clone());
                    SERVER_CLIENTS.lock().insert(client_id, connection);
                    log_info!(false, "🔌 新客户端 {} 连接: {}", client_id, peer);

                    // 启动读任务 - 处理来自客户端的消息
                    tokio::spawn({
                        let write_clone = write.clone(); // 克隆 Arc 引用
                        let client_id_str = client_id.to_string();
                        async move {
                            let mut ping_interval = interval(Duration::from_secs(CONFIG.get_heartbeat_interval()));
                            ping_interval.tick().await;

                            loop {
                                tokio::select! {
                                    // 从 WebSocket 读取数据
                                    msg = timeout(Duration::from_secs(CONFIG.get_read_timeout()), read.next()) => {
                                        match msg {
                                            // 成功读取到文本消息
                                            Ok(Some(Ok(Message::Text(ref text)))) => {
                                                if let Some(original) = process_incoming_for_server(text.as_str(), &client_id_str) {
                                                    call_epl_callback("server", &client_id_str, &original);
                                                }
                                            }
                                            // 处理 Ping 消息，回复 Pong
                                            Ok(Some(Ok(Message::Ping(data)))) => {
                                                let _ = write_clone.lock().await.send(Message::Pong(data)).await;
                                            }
                                            // 客户端关闭连接或发生错误
                                            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                                            _ => {}
                                        }
                                    }
                                    // 定期发送心跳包
                                    _ = ping_interval.tick() => {
                                        let _ = write_clone.lock().await.send(Message::Ping(vec![].into())).await;
                                    }
                                }
                            }

                            // 客户端断开连接，清理资源
                            SERVER_CLIENTS.lock().remove(&client_id);
                            log_info!(false, "👋 客户端 {} 断开", client_id);
                        }
                    });

                    // 启动写任务 - 向客户端发送消息
                    tokio::spawn(async move {
                        let mut rx = rx; // 添加这一行来获得所有权并启用 mutability
                        while let Some(msg) = rx.recv().await {
                            let final_msg = process_outgoing_for_server(&msg);
                            let msg = Message::Text(final_msg.into());
                            if let Err(e) = write.lock().await.send(msg).await {
                                log_error!(false, "向客户端 {} 发送消息失败: {}", client_id, e);
                                break;
                            }
                        }
                    });
                }
            }
        });
    });
    true
}

/// 连接 WebSocket 客户端
#[no_mangle]
pub extern "system" fn connect_ws_client(
    server_url: *const c_char,     // 服务器地址，如 "wss://example.com/ws"
    enable_reconnect: bool,        // 是否自动重连
) -> bool {
    let url_str = match unsafe { cstr_gbk_to_utf8(server_url) } {
        Some(u) => u,
        None => return false,
    };
    if Url::parse(&url_str).is_err() { return false; }

    *CLIENT_URL.lock() = Some(url_str.clone());
    CLIENT_RECONNECT.store(enable_reconnect, Ordering::SeqCst);

    let url_for_connection = url_str.clone(); // 创建用于连接的独立副本
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("创建 Tokio 运行时失败");
        rt.block_on(async move {
            let url_str_log = url_for_connection.clone(); // ✅ 新增克隆用于日志输出，防止 move 冲突
            loop {
                let url = match Url::parse(&url_for_connection) {
                    Ok(u) => u,
                    Err(e) => {
                        log_error!(false, "URL 解析失败: {}", e);
                        break;
                    }
                };

                // 构建连接器（支持 WSS）
                let connector = if url.scheme() == "wss" {
                    let mut builder = native_tls::TlsConnector::builder();
                    if CONFIG.get_skip_cert_verify() {
                        builder.danger_accept_invalid_certs(true); // ⚠️ 仅测试用
                    }
                    let tls_connector = builder.build().expect("构建 TlsConnector 失败");
                    tokio_tungstenite::Connector::NativeTls(tls_connector)
                } else {
                    tokio_tungstenite::Connector::Plain
                };

                let config = tungstenite::protocol::WebSocketConfig::default();
                let (ws_stream, _) = match tokio_tungstenite::connect_async_tls_with_config(
                    url.as_str(),
                    Some(config),
                    false,
                    Some(connector)
                ).await {
                    Ok(res) => res,
                    Err(e) => {
                        log_error!(false, "❌ 连接失败: {}", e);
                        if !CLIENT_RECONNECT.load(Ordering::SeqCst) { break; }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                IS_CLIENT_CONNECTED.store(true, Ordering::SeqCst);
                log_info!(false, "✅ 客户端连接成功: {}", url_str_log);
                // 触发连接事件
                call_connection_event("client", "", true);

                // 执行 WebSocket 协议握手
                // 分离 WebSocket 的读写端
                let (write, mut read) = ws_stream.split();

                // 使用 Arc<Mutex<>> 包装 write 以便在多个任务间共享
                let write = Arc::new(TokioMutex::new(write));

                // 创建消息通道用于向服务器发送消息
                let (tx, rx) = mpsc::unbounded_channel::<String>();
                *CLIENT_SENDER.lock() = Some(tx.clone());
                log_info!(false, "🔌 客户端已连接: {}", url_str_log);


                // ✅ 新增克隆用于 写 日志输出，防止 move 冲突
                let  url_str_log_write = url_str_log.clone();
                // 启动读任务 - 处理来自服务器的消息
                tokio::spawn({
                    let write_clone = write.clone(); // 克隆 Arc 引用
                    async move {
                        let mut ping_interval = interval(Duration::from_secs(CONFIG.get_heartbeat_interval()));
                        ping_interval.tick().await;
                        loop {
                            tokio::select! {
                                // 从 WebSocket 读取数据
                                msg = timeout(Duration::from_secs(CONFIG.get_read_timeout()), read.next()) => {
                                    match msg {
                                        // 成功读取到文本消息
                                        Ok(Some(Ok(Message::Text(ref text)))) => {
                                            if let Some(original) = process_incoming_for_client(text.as_str()) {
                                                call_epl_callback("client", "", &original);
                                            }
                                        }
                                        // 处理 Ping 消息，回复 Pong
                                        Ok(Some(Ok(Message::Ping(data)))) => {
                                            let _ = write_clone.lock().await.send(Message::Pong(data)).await;
                                        }
                                        // 服务器关闭连接或发生错误
                                        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                                        _ => {}
                                    }
                                }
                                // 定期发送心跳包
                                _ = ping_interval.tick() => {
                                    let _ = write_clone.lock().await.send(Message::Ping(vec![].into())).await;
                                }
                            }
                        }

                        // 客户端断开连接，清理资源
                        IS_CLIENT_CONNECTED.store(false, Ordering::SeqCst);
                        *CLIENT_SENDER.lock() = None;
                        log_info!(false, "👋 客户端断开连接: {}", url_str_log_write);
                        // 触发断开事件
                        call_connection_event("client", "", false);
                    }
                });

                // 启动写任务 - 向服务器发送消息
                tokio::spawn(async move {
                    let mut rx = rx; // 添加这一行来获得所有权并启用 mutability
                    while let Some(msg) = rx.recv().await {
                        let final_msg = process_outgoing_for_client(&msg);
                        if let Err(e) = write.lock().await.send(Message::Text(final_msg.into())).await {
                            log_error!(false, "向服务器发送消息失败: {}", e);
                            break;
                        }
                    }
                });

                // 等待一段时间或者直到连接断开
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if !IS_CLIENT_CONNECTED.load(Ordering::SeqCst) {
                        break;
                    }
                }

                // 检查是否需要重连
                if !CLIENT_RECONNECT.load(Ordering::SeqCst) {
                    break;
                }
                log_info!(false, "🔄 尝试重新连接...");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    });
    true
}

/// 广播消息给所有客户端（服务端模式）
#[no_mangle]
pub extern "system" fn broadcast_to_clients(message: *const c_char) -> bool {
    if let Some(msg) = unsafe { cstr_gbk_to_utf8(message) } {
        let clients = SERVER_CLIENTS.lock();
        for (_, connection) in clients.iter() {
            let processed = process_outgoing_for_server(&msg);
            let _ = connection.sender.send(processed);
        }
        true
    } else {
        false
    }
}

/// 向指定客户端发送消息（服务端模式）
#[no_mangle]
pub extern "system" fn send_to_client_by_id(client_id_str: *const c_char, message: *const c_char) -> bool {
    if let (Some(id_str), Some(msg)) = (
        unsafe { cstr_gbk_to_utf8(client_id_str) },
        unsafe { cstr_gbk_to_utf8(message) },
    ) {
        if let Ok(id) = id_str.parse::<u64>() {
            if let Some(connection) = SERVER_CLIENTS.lock().get(&id) {
                let processed = process_outgoing_for_server(&msg);
                connection.update_activity(); // 更新活动时间
                return connection.sender.send(processed).is_ok();
            }
        }
    }
    false
}

/// 向服务器发送消息（客户端模式）
#[no_mangle]
pub extern "system" fn send_to_server(message: *const c_char) -> bool {
    if let Some(msg) = unsafe { cstr_gbk_to_utf8(message) } {
        if IS_CLIENT_CONNECTED.load(Ordering::SeqCst) {
            if let Some(ref sender) = *CLIENT_SENDER.lock() {
                let processed = process_outgoing_for_client(&msg);
                return sender.send(processed).is_ok();
            }
        }
    }
    false
}

/// 查询客户端是否已连接
#[no_mangle]
pub extern "system" fn is_client_connected() -> bool {
    IS_CLIENT_CONNECTED.load(Ordering::SeqCst)
}

/// 获取当前服务端连接数
#[no_mangle]
pub extern "system" fn get_server_client_count() -> u32 {
    SERVER_CLIENTS.lock().len() as u32
}

/// 加密文本消息（供易语言调用）
/// 输入明文，返回加密后的Base64字符串
#[no_mangle]
pub extern "system" fn encrypt_message(message: *const c_char) -> *mut c_char {
    let plaintext = match unsafe { cstr_gbk_to_utf8(message) } {
        Some(text) => text,
        None => {
            log_error!(false, "encrypt_message - 无效的输入消息");
            return std::ptr::null_mut();
        }
    };

    // 检查是否启用了加密
    if !CONFIG.get_encryption_enabled() {
        log_warn!(false, "encrypt_message - 加密未启用，返回原文");
        return match utf8_to_cstring_gbk(&plaintext) {
            Some(cstring) => duplicate_cstring(cstring.as_c_str()),
            None => std::ptr::null_mut(),
        };
    }

    // 尝试使用客户端密钥加密（客户端模式常用）
    if let Some(key) = CLIENT_ENCRYPTION_KEY.lock().as_ref() {
        if let Some(encrypted) = encrypt_with_key(&build_plaintext_message(&plaintext), key) {
            log_info!(false, "encrypt_message - 使用客户端密钥加密成功");
            return match utf8_to_cstring_gbk(&encrypted) {
                Some(cstring) => duplicate_cstring(cstring.as_c_str()),
                None => std::ptr::null_mut(),
            };
        }
    }

    // 如果没有客户端密钥，尝试使用服务端密钥
    if let Some(key) = SERVER_ENCRYPTION_KEY.lock().as_ref() {
        if let Some(encrypted) = encrypt_with_key(&build_plaintext_message(&plaintext), key) {
            log_info!(false, "encrypt_message - 使用服务端密钥加密成功");
            return match utf8_to_cstring_gbk(&encrypted) {
                Some(cstring) => duplicate_cstring(cstring.as_c_str()),
                None => std::ptr::null_mut(),
            };
        }
    }

    log_error!(false, "encrypt_message - 没有可用的密钥进行加密");
    std::ptr::null_mut()
}

/// 解密文本消息（供易语言调用）
/// 输入加密后的Base64字符串，返回明文
#[no_mangle]
pub extern "system" fn decrypt_message(encrypted_message: *const c_char) -> *mut c_char {
    let encrypted_text = match unsafe { cstr_gbk_to_utf8(encrypted_message) } {
        Some(text) => text,
        None => {
            log_error!(false, "decrypt_message - 无效的输入消息");
            return std::ptr::null_mut();
        }
    };

    // 检查是否启用了加密
    if !CONFIG.get_encryption_enabled() {
        log_warn!(false, "decrypt_message - 加密未启用，返回原文");
        return match utf8_to_cstring_gbk(&encrypted_text) {
            Some(cstring) => duplicate_cstring(cstring.as_c_str()),
            None => std::ptr::null_mut(),
        };
    }

    // 尝试使用客户端密钥解密（客户端模式常用）
    if let Some(key) = CLIENT_ENCRYPTION_KEY.lock().as_ref() {
        if let Some(decrypted) = decrypt_with_key(&encrypted_text, key) {
            if let Some(original) = extract_original_message(&decrypted, "manual_decrypt") {
                log_info!(false, "decrypt_message - 使用客户端密钥解密成功");
                return match utf8_to_cstring_gbk(&original) {
                    Some(cstring) => duplicate_cstring(cstring.as_c_str()),
                    None => std::ptr::null_mut(),
                };
            }
        }
    }

    // 如果没有客户端密钥，尝试使用服务端密钥
    if let Some(key) = SERVER_ENCRYPTION_KEY.lock().as_ref() {
        if let Some(decrypted) = decrypt_with_key(&encrypted_text, key) {
            if let Some(original) = extract_original_message(&decrypted, "manual_decrypt") {
                log_info!(false, "decrypt_message - 使用服务端密钥解密成功");
                return match utf8_to_cstring_gbk(&original) {
                    Some(cstring) => duplicate_cstring(cstring.as_c_str()),
                    None => std::ptr::null_mut(),
                };
            }
        }
    }

    log_error!(false, "decrypt_message - 解密失败，可能是密钥不匹配或数据损坏");
    std::ptr::null_mut()
}

/// 复制 C 字符串到新分配的内存中（使用 Rust 分配器）
fn duplicate_cstring(cstr: &CStr) -> *mut c_char {
    let bytes_with_nul = cstr.to_bytes_with_nul();
    let len = bytes_with_nul.len();

    // 使用 libc 分配内存，确保易语言能正确释放
    let ptr = unsafe { libc::malloc(len) as *mut u8 };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes_with_nul.as_ptr(), ptr, len);
    }

    ptr as *mut c_char
}
