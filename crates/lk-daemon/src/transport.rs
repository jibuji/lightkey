//! 本地 IPC 传输层（规格：`docs/ipc.md` §2/§6；M2 决策 #3 A 推送通道）。
//!
//! - Unix domain socket（macOS/Linux，0600）/ Windows named pipe（仅本用户，
//!   随机 pipe 名 + 用户私有数据目录）。
//! - 帧：单行 JSON（`\n` 结尾）；常规连接一请求一响应。
//! - **通知订阅连接**（决策 #3 A）：客户端连接后发 `subscribe`（携带会话
//!   令牌），校验通过 → 连接转入流模式——守护进程后续对该连接主动写
//!   JSON-RPC notification 帧（无 `id`，一行一帧）。`lk inject` 不走订阅
//!   连接（阻塞式 `authz.evaluate`）。
//! - 对端身份（[`PeerInfo`]）：PID（unix `SO_PEERCRED` / Windows
//!   `GetNamedPipeClientProcessId`）+ 真实 cwd（`lk_core::starter`）——授权
//!   路径据此回溯启动者，**不信任客户端自报字段**。
//! - socket/pipe 路径含用户级随机组件，且位于用户私有数据目录（0700）——
//!   防跨用户劫持。
//! - 守护进程信息（pid + 端点 + `version`）写入 `daemon.json`；客户端首次
//!   访问自动拉起守护进程（陈旧端点处置见 [`ensure_daemon`]：pid 不存活
//!   仅清理；pid 存活须连续多次探测失败才判僵死 kill，绝不单次 probe
//!   瞬态失败即杀——宁可少杀，不可误杀，#31）。
//!   `version` 供协议版本校验（cross-subsystem.md §7.3），旧文件缺省可读。
//! - Windows named pipe 服务端任意时刻常备 ≥1 个监听实例（先补位再派发），
//!   响应写完先 `FlushFileBuffers` 再断连（#31）；客户端连接对 233 /
//!   FILE_NOT_FOUND 瞬态窗口做有界短重试。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 守护进程端点信息（数据目录下 `daemon.json`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub pid: u32,
    /// unix: socket 绝对路径；windows: 完整 pipe 名。
    pub address: String,
    /// 守护进程版本（cross-subsystem.md §7.3 协议版本校验）。
    /// 旧格式 `daemon.json` 无此字段 → `None`（serde default，向后兼容）。
    #[serde(default)]
    pub version: Option<String>,
}

/// 请求处理器类型（行 + 对端身份 → 响应行）。
pub type Handler = Arc<dyn Fn(&str, &PeerInfo) -> String + Send + Sync>;

/// IPC 对端身份（传输层在连接建立时派生；授权路径据此判定启动者与 cwd）。
#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    /// 对端进程 PID（0 = 未知 → 授权 fail-closed）。
    pub pid: u32,
    /// 对端进程真实 cwd（canonical 形态；`None` = 未知 → 授权 fail-closed）。
    pub cwd: Option<String>,
}

impl PeerInfo {
    /// 未知对端（测试/无法获取的平台路径）。
    pub fn unknown() -> PeerInfo {
        PeerInfo::default()
    }
}

/// 通知订阅注册表（跨线程：命令线程广播 → 每订阅连接一个 writer 线程排空）。
///
/// [`PushHub::broadcast`] 只做内存 channel 投递（**非阻塞**，符合总线契约）；
/// socket 写入由订阅连接自己的 writer 线程承担。客户端慢/死 → 内存队列
/// 增长（桌面持续读取；死连接写入失败即退订）。
pub struct PushHub {
    subs: Mutex<std::collections::HashMap<u64, mpsc::Sender<String>>>,
    next_id: AtomicU64,
}

impl PushHub {
    pub fn new() -> Arc<PushHub> {
        Arc::new(PushHub {
            subs: Mutex::new(std::collections::HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    /// 登记订阅者，返回 (订阅者 id, 帧接收端)。writer 线程排空接收端。
    pub fn subscribe(&self) -> (u64, mpsc::Receiver<String>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.subs.lock().unwrap().insert(id, tx);
        (id, rx)
    }

    /// 退订（writer 线程退出时调用；幂等）。
    pub fn unsubscribe(&self, id: u64) {
        self.subs.lock().unwrap().remove(&id);
    }

    /// 广播一帧给全部订阅者（非阻塞内存投递）。
    pub fn broadcast(&self, frame: &str) {
        let subs: Vec<mpsc::Sender<String>> = self.subs.lock().unwrap().values().cloned().collect();
        for tx in subs {
            let _ = tx.send(frame.to_string());
        }
    }

    /// 订阅连接数（0 = 桌面壳未运行 = 无审批界面 → 第 3 层 fail-closed）。
    pub fn subscriber_count(&self) -> usize {
        self.subs.lock().unwrap().len()
    }
}

pub fn daemon_json_path(dir: &Path) -> PathBuf {
    dir.join("daemon.json")
}

pub fn read_endpoint(dir: &Path) -> Option<Endpoint> {
    let bytes = std::fs::read(daemon_json_path(dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_endpoint(dir: &Path, ep: &Endpoint) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(ep).expect("端点信息可序列化");
    let tmp = daemon_json_path(dir).with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, daemon_json_path(dir))?;
    Ok(())
}

/// 是否为订阅请求（连接首行；由传输层识别并转流模式）。
fn is_subscribe_request(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string))
        .map(|m| m == lk_core::ipc::M_SUBSCRIBE)
        .unwrap_or(false)
}

/// 订阅响应是否成功（有 result 且无 error → 转流模式；token 无效 →
/// `session.invalid` → 保持常规连接，一请求一响应后关闭）。
fn subscribe_response_ok(resp: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(resp)
        .ok()
        .map(|v| v.get("error").is_none() && v.get("result").is_some())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Unix domain socket
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    /// 对端 PID（SO_PEERCRED；macOS 无对等通道 → 0 = 未知 → fail-closed）。
    #[cfg(target_os = "linux")]
    fn peer_pid(stream: &UnixStream) -> u32 {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as u32;
            let r = libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if r == 0 {
                cred.pid as u32
            } else {
                0
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn peer_pid(_stream: &UnixStream) -> u32 {
        0 // macOS：UDS 无对端 PID 通道 → 授权 fail-closed（starter=unknown）
    }

    /// 对端身份：PID + 真实 cwd（canonical）。
    fn peer_info(stream: &UnixStream) -> PeerInfo {
        let pid = peer_pid(stream);
        let cwd = if pid != 0 {
            lk_core::starter::resolve_peer_cwd(pid)
        } else {
            None
        };
        PeerInfo { pid, cwd }
    }

    /// 绑定监听 socket：`<dir>/run/lk-<随机8hex>.sock`（0700 目录 + 0600 socket）。
    pub fn bind(dir: &Path) -> std::io::Result<UnixListener> {
        let run = dir.join("run");
        std::fs::create_dir_all(&run)?;
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))?;
        // 清理上一轮遗留（崩溃残留；同用户同目录，安全）
        let sock = run.join(format!(
            "lk-{}.sock",
            hex::encode(lk_core::crypto::random_array::<8>())
        ));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        let ep = Endpoint {
            pid: std::process::id(),
            address: sock.to_string_lossy().to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };
        write_endpoint(dir, &ep)?;
        Ok(listener)
    }

    /// 监听并处理连接（每连接一线程；订阅连接转流模式）。
    pub fn serve(
        listener: UnixListener,
        handler: Handler,
        hub: Option<Arc<PushHub>>,
        shutdown: &'static AtomicBool,
    ) -> std::io::Result<()> {
        // 非阻塞 accept + 轮询 shutdown，保证 SIGTERM/SIGINT 能优雅退出
        listener.set_nonblocking(true)?;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let handler = handler.clone();
                    let hub = hub.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(300)));
                        let peer = peer_info(&stream);
                        let mut s = stream;
                        if let Ok(Some(line)) = read_line(&mut s) {
                            // 订阅连接：转入流模式（守护进程主动推送通知帧）
                            if is_subscribe_request(&line) {
                                let resp = handler(&line, &peer);
                                let _ = write_line(&mut s, &resp);
                                if subscribe_response_ok(&resp) {
                                    if let Some(hub) = hub {
                                        serve_push_stream(s, &hub);
                                    }
                                }
                                return;
                            }
                            let resp = handler(&line, &peer);
                            let _ = write_line(&mut s, &resp);
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// 订阅连接流模式：writer 线程排空通知帧写 socket；主线程读到对端关闭
    /// 即退出（writer 线程随后退订）。
    fn serve_push_stream(stream: UnixStream, hub: &Arc<PushHub>) {
        let (id, rx) = hub.subscribe();
        let closed = Arc::new(AtomicBool::new(false));
        let writer_stream = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => {
                hub.unsubscribe(id);
                return;
            }
        };
        let hub = Arc::clone(hub);
        let c = Arc::clone(&closed);
        let writer = std::thread::spawn(move || {
            let mut ws = writer_stream;
            loop {
                if c.load(Ordering::Relaxed) {
                    break;
                }
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(frame) => {
                        if write_line(&mut ws, &frame).is_err() {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            hub.unsubscribe(id);
        });
        // 主线程：读（忽略内容——订阅连接不再承载请求）直到对端关闭
        let mut reader = stream;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        closed.store(true, Ordering::Relaxed);
        let _ = writer.join();
    }

    /// 客户端连接。
    pub fn connect(ep: &Endpoint) -> std::io::Result<UnixStream> {
        let stream = UnixStream::connect(&ep.address)?;
        stream.set_read_timeout(Some(Duration::from_secs(300)))?;
        stream.set_write_timeout(Some(Duration::from_secs(300)))?;
        Ok(stream)
    }

    /// 读一行（到 `\n` 为止，无长度上限——附件整包可达数十 MB）。
    pub fn read_line(stream: &mut impl Read) -> std::io::Result<Option<String>> {
        let mut buf = Vec::with_capacity(4096);
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(String::from_utf8_lossy(&buf).to_string()));
                }
                Ok(_) => {
                    if byte[0] == b'\n' {
                        return Ok(Some(String::from_utf8_lossy(&buf).to_string()));
                    }
                    buf.push(byte[0]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// 写一行（`\n` 结尾）。
    pub fn write_line(stream: &mut impl Write, line: &str) -> std::io::Result<()> {
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()
    }

    /// 进程是否存活。
    pub fn pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    /// 终止进程。
    pub fn kill_pid(pid: u32) {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    /// 清理端点文件与 socket。
    pub fn cleanup(dir: &Path, ep: &Endpoint) {
        let _ = std::fs::remove_file(&ep.address);
        let _ = std::fs::remove_file(daemon_json_path(dir));
    }
}

// ---------------------------------------------------------------------------
// Windows named pipe
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, TerminateProcess};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    // ERROR_PIPE_BUSY(231) 等连接错误码移至模块级公共区（connect_with_retry）
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const PROCESS_TERMINATE: u32 = 0x0001;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 对端身份：PID（GetNamedPipeClientProcessId）+ 真实 cwd（PEB 读取）。
    fn peer_info(handle: HANDLE) -> PeerInfo {
        let mut pid: u32 = 0;
        let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) };
        let pid = if ok != 0 { pid } else { 0 };
        let cwd = if pid != 0 {
            lk_core::starter::resolve_peer_cwd(pid)
        } else {
            None
        };
        PeerInfo { pid, cwd }
    }

    /// 复制句柄（订阅连接 writer 线程与主线程各持一份）。
    fn dup_handle(h: HANDLE) -> Option<HANDLE> {
        unsafe {
            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = DuplicateHandle(
                GetCurrentProcess(),
                h,
                GetCurrentProcess(),
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if ok == 0 {
                None
            } else {
                Some(dup)
            }
        }
    }

    /// 生成 pipe 名：`\\.\pipe\lightkey-<user>-<随机8hex>`（用户级随机组件防劫持）。
    pub fn bind(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
        let rand = hex::encode(lk_core::crypto::random_array::<8>());
        let pipe_name = format!("\\\\.\\pipe\\lightkey-{user}-{rand}");
        let ep = Endpoint {
            pid: std::process::id(),
            address: pipe_name,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };
        write_endpoint(dir, &ep)?;
        Ok(())
    }

    /// 仅限当前用户的 pipe 安全属性（ipc.md §2「pipe ACL」，A2）。
    ///（M1.5 既有实现：显式 DACL 仅授予当前用户 SID；注释见原实现。）
    struct UserOnlySa {
        attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
        _sd: Box<windows_sys::Win32::Security::SECURITY_DESCRIPTOR>,
        _acl: Vec<u8>,
    }

    fn user_only_sa() -> std::io::Result<UserOnlySa> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAce, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
            SetSecurityDescriptorDacl, TokenUser, ACL, ACL_REVISION, PSECURITY_DESCRIPTOR, PSID,
            SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        const GENERIC_ALL: u32 = 0x1000_0000;
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut user_buf = [0u8; 128];
            let mut ret_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                user_buf.as_mut_ptr() as *mut core::ffi::c_void,
                user_buf.len() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token);
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let user = &*(user_buf.as_ptr() as *const TOKEN_USER);
            let sid: PSID = user.User.Sid;

            let mut acl_buf = vec![0u8; 256];
            let acl = acl_buf.as_mut_ptr() as *mut ACL;
            if InitializeAcl(acl, acl_buf.len() as u32, ACL_REVISION) == 0
                || AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(std::mem::zeroed());
            if InitializeSecurityDescriptor(
                sd.as_mut() as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
                SECURITY_DESCRIPTOR_REVISION,
            ) == 0
                || SetSecurityDescriptorDacl(
                    sd.as_mut() as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
                    1,
                    acl,
                    0,
                ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.as_mut() as *mut SECURITY_DESCRIPTOR
                    as *mut core::ffi::c_void,
                bInheritHandle: 0,
            };
            Ok(UserOnlySa {
                attrs,
                _sd: sd,
                _acl: acl_buf,
            })
        }
    }

    /// 创建一个监听中的 pipe 实例（#31：服务端任意时刻常备 ≥1 个）。
    fn create_pipe_instance(name: &[u16], sa: &UserOnlySa) -> std::io::Result<HANDLE> {
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa.attrs as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(handle)
        }
    }

    /// 监听并处理连接（每连接一线程；订阅连接转流模式）。
    ///
    /// #31 实例池化：循环外预创建首个监听实例；`ConnectNamedPipe` 返回
    /// （客户端已连入）后**先补位**（创建下一个监听实例）**再派发**处理线程。
    /// 旧实现单实例串行 `CreateNamedPipeW → ConnectNamedPipe`，实例已建但未进
    /// 监听的窗口期内客户端 `CreateFileW` 可成功拿到句柄，后续 I/O 即 os error
    /// 233（ERROR_PIPE_NOT_CONNECTED），probe 撞上该竞态进而误杀健康守护。
    /// 补位失败则关闭已连入句柄并向上报错（宁可让单个客户端失败重试，不留无
    /// 监听窗口）；协议格式与授权语义零变更。
    pub fn serve(
        dir: &Path,
        handler: Handler,
        hub: Option<Arc<PushHub>>,
        shutdown: &'static AtomicBool,
    ) -> std::io::Result<()> {
        let ep = read_endpoint(dir)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "缺少 daemon.json"))?;
        let name = wide(&ep.address);
        let sa = user_only_sa()?;
        // #31：循环外预创建首个监听实例（bind 写 daemon.json 与首个实例进入
        // 监听之间不再有窗口）
        let mut listening = create_pipe_instance(&name, &sa)?;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                unsafe {
                    CloseHandle(listening);
                }
                break;
            }
            let ok = unsafe { ConnectNamedPipe(listening, std::ptr::null_mut()) };
            if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                // 客户端连入后即刻断开等瞬态失败：弃置该实例并重建监听实例，
                // 监听常备性不受影响
                unsafe {
                    CloseHandle(listening);
                }
                listening = create_pipe_instance(&name, &sa)?;
                continue;
            }
            let connected = listening;
            // 先补位再派发：消除「无监听实例」窗口（补位失败则关闭已连入
            // 句柄并向上报错，由调用方/客户端重试兜底）
            listening = match create_pipe_instance(&name, &sa) {
                Ok(h) => h,
                Err(e) => {
                    unsafe {
                        CloseHandle(connected);
                    }
                    return Err(e);
                }
            };
            let handler = handler.clone();
            let hub = hub.clone();
            let peer = peer_info(connected);
            // 先包装成 SendHandle 再入闭包（裸 HANDLE 非 Send）
            let sh = SendHandle(connected);
            std::thread::spawn(move || {
                let mut stream = PipeStream { handle: sh };
                if let Ok(Some(line)) = read_line(&mut stream) {
                    if is_subscribe_request(&line) {
                        let resp = handler(&line, &peer);
                        let _ = write_line(&mut stream, &resp);
                        if subscribe_response_ok(&resp) {
                            if let Some(hub) = hub {
                                serve_push_stream(&mut stream, &hub);
                            }
                        }
                    } else {
                        let resp = handler(&line, &peer);
                        let _ = write_line(&mut stream, &resp);
                    }
                }
                // 响应阶段竞态（#31）：写完立即 `DisconnectNamedPipe` 会在客户端
                // 尚未读走管道缓冲区内响应时把数据随断连丢弃（字节模式实测服务端
                // 写完 ~37µs 即断连，慢读客户端拿到截断响应/UnexpectedEof——再经
                // probe 放大成误杀）。named pipe 服务端的 `FlushFileBuffers` 阻塞
                // 至客户端读走全部已写数据，是「确保送达再断连」的正确原语。
                // 客户端已先行断开时它返回 ERROR_PIPE_NOT_CONNECTED(233)：响应
                // 本就无人接收，忽略；其余失败同样不阻断断连路径。阻塞风险取舍：
                // 若客户端拿到响应帧后不再读取，本调用无限期阻塞——与既有模型一致
                // （连接线程本就以 PIPE_WAIT 无超时阻塞在请求行读取，每连接独立
                // 线程，不拖垮守护进程主循环），故不加定时器兜底；纯 sleep 宽限是
                // 下策（不保证送达且平添固定延迟）。
                //
                // TODO(CI): Windows named pipe 真实行为无法在 Linux 单测覆盖，
                // 由下方 windows-only 慢读回归锁单测 + CI windows-latest / 真机
                // E2E 复测确认归零。
                unsafe {
                    let _ = FlushFileBuffers(sh.0);
                    DisconnectNamedPipe(sh.0);
                    CloseHandle(sh.0);
                }
            });
        }
        Ok(())
    }

    /// 订阅连接流模式（Windows：DuplicateHandle 拆读写两端）。
    fn serve_push_stream(stream: &mut PipeStream, hub: &Arc<PushHub>) {
        let Some(writer_handle) = dup_handle(stream.handle.0) else {
            return;
        };
        let (id, rx) = hub.subscribe();
        let closed = Arc::new(AtomicBool::new(false));
        let hub = Arc::clone(hub);
        let c = Arc::clone(&closed);
        let sh = SendHandle(writer_handle); // 先包装再入闭包（裸句柄非 Send）
        let writer = std::thread::spawn(move || {
            let mut ws = PipeStream { handle: sh };
            loop {
                if c.load(Ordering::Relaxed) {
                    break;
                }
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(frame) => {
                        if write_line(&mut ws, &frame).is_err() {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            unsafe {
                CloseHandle(sh.0);
            }
            hub.unsubscribe(id);
        });
        // 主线程：读（忽略内容）直到对端关闭
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        closed.store(true, Ordering::Relaxed);
        let _ = writer.join();
    }

    /// HANDLE 是裸指针，跨线程移动需要显式 Send（句柄本质是整数，安全）。
    #[derive(Clone, Copy)]
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}

    pub struct PipeStream {
        handle: SendHandle,
    }

    impl Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(read as usize)
            }
        }
    }

    impl Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle.0,
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn read_line(stream: &mut impl Read) -> std::io::Result<Option<String>> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(String::from_utf8_lossy(&buf).to_string()));
                }
                Ok(n) => {
                    if let Some(pos) = chunk[..n].iter().position(|&b| b == b'\n') {
                        buf.extend_from_slice(&chunk[..pos]);
                        return Ok(Some(String::from_utf8_lossy(&buf).to_string()));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn write_line(stream: &mut impl Write, line: &str) -> std::io::Result<()> {
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()
    }

    /// 客户端连接：注入 [`connect_with_retry`] 驱动（错误码语义见其文档）。
    pub fn connect(ep: &Endpoint) -> std::io::Result<PipeStream> {
        let name = wide(&ep.address);
        connect_with_retry(
            || {
                let handle = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        INVALID_HANDLE_VALUE,
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    Ok(PipeStream {
                        handle: SendHandle(handle),
                    })
                } else {
                    Err(unsafe { GetLastError() })
                }
            },
            || unsafe { WaitNamedPipeW(name.as_ptr(), 10_000) != 0 },
        )
    }

    /// 进程是否存活（OpenProcess 失败时句柄为 NULL——非
    /// INVALID_HANDLE_VALUE；对已退出 pid 返回 false）。
    pub fn pid_alive(pid: u32) -> bool {
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h.is_null() {
            return false;
        }
        unsafe {
            CloseHandle(h);
        }
        true
    }

    pub fn kill_pid(pid: u32) {
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if !h.is_null() {
            unsafe {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
    }

    pub fn cleanup(dir: &Path, _ep: &Endpoint) {
        // named pipe 随最后一个句柄关闭而销毁；只需清理端点文件
        let _ = std::fs::remove_file(daemon_json_path(dir));
    }
}

// ---------------------------------------------------------------------------
// 公共接口（cfg 分发）
// ---------------------------------------------------------------------------

pub use imp::{cleanup, connect, kill_pid, pid_alive, read_line, write_line};

/// 绑定服务端（写入 daemon.json）。unix 返回监听器；windows 仅注册端点。
#[cfg(unix)]
pub fn bind_server(dir: &Path) -> std::io::Result<std::os::unix::net::UnixListener> {
    ensure_user_dir(dir)?;
    imp::bind(dir)
}

#[cfg(windows)]
pub fn bind_server(dir: &Path) -> std::io::Result<()> {
    ensure_user_dir(dir)?;
    imp::bind(dir)
}

/// 服务主循环。
#[cfg(unix)]
pub fn serve(
    listener: std::os::unix::net::UnixListener,
    handler: Handler,
    hub: Option<Arc<PushHub>>,
    shutdown: &'static AtomicBool,
) -> std::io::Result<()> {
    imp::serve(listener, handler, hub, shutdown)
}

#[cfg(windows)]
pub fn serve(
    dir: &Path,
    handler: Handler,
    hub: Option<Arc<PushHub>>,
    shutdown: &'static AtomicBool,
) -> std::io::Result<()> {
    imp::serve(dir, handler, hub, shutdown)
}

fn ensure_user_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 客户端：请求 / 自动拉起
// ---------------------------------------------------------------------------

/// win32 named pipe 连接错误码（平台无关重试驱动 [`connect_with_retry`] 的
/// 输入语义；Windows connect 注入真实 CreateFileW 结果）。
#[cfg(any(windows, test))]
const ERROR_PIPE_BUSY: u32 = 231;
/// ERROR_PIPE_NOT_CONNECTED：服务端「实例已建未监听/已连入未派发」瞬态窗口。
#[cfg(any(windows, test))]
const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
/// ERROR_FILE_NOT_FOUND：守护刚拉起、首个监听实例未建的启动窗口。
#[cfg(any(windows, test))]
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// 瞬态错误短重试上限（规格：有界，不无限阻塞 CLI）。
#[cfg(any(windows, test))]
const CONNECT_TRANSIENT_RETRIES: u32 = 20;

/// 发起一次 pipe 连接的重试驱动（注入式，#31）。`open` 返回连接或原始
/// win32 错误码；`wait_busy` 对应 WaitNamedPipeW 语义。处置规则：
/// - ERROR_PIPE_BUSY → 等待后重试（既有语义不变）；
/// - 233 / FILE_NOT_FOUND（#31 瞬态窗口：实例补位前 / 守护刚拉起监听未建）
///   → 有界短重试，至多 [`CONNECT_TRANSIENT_RETRIES`] 次、每次间隔
///   [`CONNECT_TRANSIENT_BACKOFF`]，超限即上抛（总时长有界，不无限阻塞 CLI）；
/// - 其余错误码不重试、立即上抛。
#[cfg(any(windows, test))]
fn connect_with_retry<T>(
    mut open: impl FnMut() -> Result<T, u32>,
    mut wait_busy: impl FnMut() -> bool,
) -> std::io::Result<T> {
    let mut transient_failures = 0u32;
    loop {
        match open() {
            Ok(t) => return Ok(t),
            Err(ERROR_PIPE_BUSY) => {
                if !wait_busy() {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Err(e)
                if (e == ERROR_PIPE_NOT_CONNECTED || e == ERROR_FILE_NOT_FOUND)
                    && transient_failures < CONNECT_TRANSIENT_RETRIES =>
            {
                transient_failures += 1;
                std::thread::sleep(CONNECT_TRANSIENT_BACKOFF);
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }
}

/// 瞬态错误相邻两次尝试的间隔。
#[cfg(any(windows, test))]
const CONNECT_TRANSIENT_BACKOFF: Duration = Duration::from_millis(10);

/// 发送一行请求并返回响应行（连接失败返回 Err）。
pub fn request(endpoint: &Endpoint, line: &str) -> std::io::Result<String> {
    let mut stream = connect(endpoint)?;
    write_line(&mut stream, line)?;
    match read_line(&mut stream) {
        Ok(Some(resp)) => Ok(resp),
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "守护进程提前关闭连接",
        )),
        Err(e) => Err(e),
    }
}

/// 确保守护进程在跑：探测端点 → 陈旧则按处置规则处理 → 拉起 → 等待就绪。
/// `dir_override` 为 `lk --dir` 的显式值（透传给子进程）。
pub fn ensure_daemon(dir: &Path) -> std::io::Result<Endpoint> {
    if let Some(ep) = read_endpoint(dir) {
        // 注入接缝：探测/存活/kill/清理可替换（单测用假序列驱动）
        let guard = StaleGuard {
            probe: &|ep| probe(ep),
            pid_alive: &|pid| pid_alive(pid),
            kill: &|pid| kill_pid(pid),
            cleanup: &|dir, ep| cleanup(dir, ep),
        };
        if resolve_existing_daemon(dir, &ep, &guard) {
            return Ok(ep);
        }
    }
    spawn_daemon(dir)?;
    // 轮询等待就绪（最多 ~5s）
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(ep) = read_endpoint(dir) {
            if probe(&ep) {
                return Ok(ep);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "守护进程启动超时",
    ))
}

/// 陈旧端点处置的注入接缝：四个副作用边界均可替换——单测喂假 probe 序列并
/// 观察 kill 是否发生；生产路径由 [`ensure_daemon`] 接真实实现。
struct StaleGuard<'a> {
    probe: &'a dyn Fn(&Endpoint) -> bool,
    pid_alive: &'a dyn Fn(u32) -> bool,
    kill: &'a dyn Fn(u32),
    cleanup: &'a dyn Fn(&Path, &Endpoint),
}

/// 处置既有端点：返回 true 表示端点健康可复用（调用方直接使用）；false 表示
/// 已完成陈旧处置（调用方拉起新守护进程）。
///
/// 判死状态机（#31，fail-safe 方向：宁可少杀，不可误杀）：
/// - probe 通过 → 健康，复用；
/// - probe 失败 + **pid 已死** → 陈旧端点，仅清理（PID 可能已易主，绝不 kill）；
/// - probe 失败 + pid 存活 → 疑似僵死，但单次失败可能是管道瞬态竞态——
///   先走重试梯（含首探共 [`PROBE_RETRIES_AFTER_LIVENESS`] 次、等距间隔
///   [`PROBE_RETRY_DELAY`]），任一次恢复即复用；连续失败才 kill。
fn resolve_existing_daemon(dir: &Path, ep: &Endpoint, g: &StaleGuard) -> bool {
    if (g.probe)(ep) {
        return true;
    }
    if !(g.pid_alive)(ep.pid) {
        // pid 已不存活：清理即可，无须也绝不应 kill
        (g.cleanup)(dir, ep);
        return false;
    }
    // pid 存活：重试梯内恢复即复用，绝不因一次瞬态失败误杀健康守护
    if probe_retry_ladder(ep, PROBE_RETRIES_AFTER_LIVENESS - 1, g.probe) {
        return true;
    }
    (g.kill)(ep.pid);
    (g.cleanup)(dir, ep);
    false
}

/// pid 存活但首探失败后的追加重试次数（含首探共 3 次）。
///
/// 注意：本值是**含首探的总探测次数**；重试梯实际补采 `值 - 1` 次
/// （首探已由 [`resolve_existing_daemon`] 计入，见调用处）。
const PROBE_RETRIES_AFTER_LIVENESS: usize = 3;

/// 相邻两次探测的间隔。
const PROBE_RETRY_DELAY: Duration = Duration::from_millis(150);

/// 重试梯：精确再采样 `attempts` 次（0 = 不补采，立即判失败）。相邻两次探测
/// 之间——含本梯首次与调用方刚失败的那次探测之间——一律先等
/// [`PROBE_RETRY_DELAY`]：三次探测必须**等距**铺开（若首发紧贴上次失败立即
/// 发出，可能落进同一毫秒级管道瞬态窗口，等于只有两次有效采样，#31）。
fn probe_retry_ladder(ep: &Endpoint, attempts: usize, probe: &dyn Fn(&Endpoint) -> bool) -> bool {
    for _ in 0..attempts {
        std::thread::sleep(PROBE_RETRY_DELAY);
        if probe(ep) {
            return true;
        }
    }
    false
}

/// 探测端点是否可用（vault.status 无需令牌，锁态也可响应）。
fn probe(ep: &Endpoint) -> bool {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": lk_core::ipc::M_VAULT_STATUS,
        "params": {}
    });
    request(ep, &req.to_string()).is_ok()
}

/// 拉起 `lk daemon --dir <dir>`（脱离终端；子进程继承 LIGHTKEY_HOME 等环境）。
fn spawn_daemon(dir: &Path) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon").arg("--dir").arg(dir);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // 独立会话，避免随终端关闭收到 SIGHUP
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    cmd.spawn()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 新格式：含 version 字段 → 解析 OK，值正确（§7.3）。
    #[test]
    fn parse_with_version() {
        let raw = format!(
            r#"{{"pid":123,"address":"/tmp/lk.sock","version":"{}"}}"#,
            env!("CARGO_PKG_VERSION")
        );
        let ep: Endpoint = serde_json::from_str(&raw).expect("新格式可解析");
        assert_eq!(ep.pid, 123);
        assert_eq!(ep.address, "/tmp/lk.sock");
        assert_eq!(ep.version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    }

    /// 旧格式：无 version 字段 → 解析 OK（向后兼容），version 为 None。
    #[test]
    fn parse_without_version() {
        let raw = r#"{"pid":42,"address":"\\\\.\\pipe\\lightkey-user-abcd"}"#;
        let ep: Endpoint = serde_json::from_str(raw).expect("旧格式可解析");
        assert_eq!(ep.pid, 42);
        assert_eq!(ep.address, "\\\\.\\pipe\\lightkey-user-abcd");
        assert_eq!(ep.version, None);
    }

    /// 序列化输出含 version 字段（守护进程写入即携带版本）。
    #[test]
    fn serialize_contains_version() {
        let ep = Endpoint {
            pid: 7,
            address: "/run/lk.sock".to_string(),
            version: Some("9.9.9".to_string()),
        };
        let out = serde_json::to_string(&ep).expect("可序列化");
        assert!(
            out.contains(r#""version":"9.9.9""#),
            "输出缺 version: {out}"
        );
        // 往返一致
        let back: Endpoint = serde_json::from_str(&out).expect("往返解析");
        assert_eq!(back.version.as_deref(), Some("9.9.9"));
    }

    // -------------------------------------------------------------------------
    // seam A「守护判死」：陈旧端点处置——注入假 probe 序列，观察 kill 是否发生
    // -------------------------------------------------------------------------

    /// seam A 假状态：probe 结果序列 + 存活旗标 + kill/cleanup 观察记录。
    ///
    /// `probe_calls` 精确记录探测总次数（含首探）——队列耗尽后假 probe 恒返
    /// false，仅凭「剩余长度」无法察觉多采样/少采样，必须用计数器钉死次数。
    #[derive(Default)]
    struct GuardFake {
        probe_results: std::collections::VecDeque<bool>,
        probe_calls: usize,
        alive: bool,
        killed: Vec<u32>,
        cleaned: bool,
    }

    thread_local! {
        static GUARD_FAKE: std::cell::RefCell<GuardFake> = std::cell::RefCell::new(GuardFake::default());
    }

    fn fake_guard() -> StaleGuard<'static> {
        StaleGuard {
            probe: &|_ep| {
                GUARD_FAKE.with(|f| {
                    let mut f = f.borrow_mut();
                    f.probe_calls += 1;
                    f.probe_results.pop_front().unwrap_or(false)
                })
            },
            pid_alive: &|_pid| GUARD_FAKE.with(|f| f.borrow().alive),
            kill: &|pid| GUARD_FAKE.with(|f| f.borrow_mut().killed.push(pid)),
            cleanup: &|_dir, _ep| GUARD_FAKE.with(|f| f.borrow_mut().cleaned = true),
        }
    }

    fn guard_fake_set(probe_results: Vec<bool>, alive: bool) {
        GUARD_FAKE.with(|f| {
            *f.borrow_mut() = GuardFake {
                probe_results: probe_results.into(),
                alive,
                ..Default::default()
            }
        });
    }

    fn guard_fake_taken() -> (Vec<u32>, bool, usize) {
        GUARD_FAKE.with(|f| {
            let f = f.borrow();
            (f.killed.clone(), f.cleaned, f.probe_calls)
        })
    }

    /// 期望值来自 issue #31 症状规格，不与实现同构重算：任何持有解锁库的
    /// 守护进程被误杀即本测试失败。
    fn hazard_ep() -> Endpoint {
        Endpoint {
            pid: 4242,
            address: r"\\.\pipe\lightkey-fake-0badf00d".to_string(),
            version: None,
        }
    }

    /// **issue #31 危害复现（红）**：单次瞬态 probe 失败 + pid 存活 →
    /// 绝不允许 kill 持有解锁库的守护进程——瞬态失败意味着下一拍即恢复，
    /// 端点必须被复用而非处死。
    #[test]
    fn single_transient_probe_failure_never_kills_live_daemon() {
        guard_fake_set(vec![false, true], true);
        let reused = resolve_existing_daemon(Path::new("/tmp/fake"), &hazard_ep(), &fake_guard());
        let (killed, cleaned, probe_calls) = guard_fake_taken();
        assert!(reused, "瞬态失败后恢复必须复用健康守护");
        assert!(
            killed.is_empty(),
            "单次瞬态失败绝不杀进程，实际 kill 了 {killed:?}"
        );
        assert!(!cleaned, "复用路径不得清理端点");
        assert_eq!(
            probe_calls, 2,
            "首探失败后必须恰好再采样一次（恢复帧被消费）即止：不得一次采样定生死，也不得多采"
        );
    }

    /// 连续失败但未达规格阈值（规格：含首探共 3 次连续失败才判僵死）→
    /// 第 3 拍恢复 → 仍不 kill、复用端点。
    #[test]
    fn failures_below_spec_threshold_still_never_kill() {
        guard_fake_set(vec![false, false, true], true);
        let reused = resolve_existing_daemon(Path::new("/tmp/fake"), &hazard_ep(), &fake_guard());
        let (killed, _, probe_calls) = guard_fake_taken();
        assert!(reused, "阈值内恢复必须复用健康守护");
        assert!(killed.is_empty());
        assert_eq!(
            probe_calls, 3,
            "含首探共恰好 3 次采样（规格阈值），第 3 拍恢复即止"
        );
    }

    /// 连续多次失败达到规格阈值且全程未恢复 + pid 存活 → 判僵死，
    /// 必须 kill（陈旧守护占位时不能永远不敢杀）。
    #[test]
    fn consecutive_probe_failures_beyond_threshold_eventually_kills() {
        guard_fake_set(vec![false, false, false], true); // 首探已计入，这里供重试梯
        let reused = resolve_existing_daemon(Path::new("/tmp/fake"), &hazard_ep(), &fake_guard());
        let (killed, cleaned, probe_calls) = guard_fake_taken();
        assert!(!reused);
        assert_eq!(killed, vec![4242], "连续失败达标后必须 kill 僵死进程");
        assert!(cleaned);
        assert_eq!(
            probe_calls, 3,
            "重试梯必须恰好耗尽（含首探共 3 次）后才允许 kill"
        );
    }

    /// probe 失败 + pid 已死 → 陈旧端点：仅清理，绝不 kill（PID 可能已易主）。
    #[test]
    fn dead_pid_endpoint_cleans_without_kill() {
        guard_fake_set(vec![false, false, false], false);
        let reused = resolve_existing_daemon(Path::new("/tmp/fake"), &hazard_ep(), &fake_guard());
        let (killed, cleaned, probe_calls) = guard_fake_taken();
        assert!(!reused);
        assert!(killed.is_empty(), "pid 已不存活无须也绝不应 kill");
        assert!(cleaned);
        assert_eq!(
            probe_calls, 1,
            "pid 已死的判定无需耗尽重试梯（首探失败即可清理）"
        );
    }

    // -------------------------------------------------------------------------
    // seam B「客户端连接重试」：注入 win32 错误序列，观察有界重试行为
    // -------------------------------------------------------------------------

    /// 期望值来自 issue #31 症状规格：守护刚拉起/实例补位前的瞬态窗口
    /// （233 / FILE_NOT_FOUND）不得让客户端连接失败；重试次数必须有界。
    #[test]
    fn transient_connect_errors_then_success_eventually_succeeds() {
        let mut script = std::collections::VecDeque::from(vec![
            Err(ERROR_PIPE_NOT_CONNECTED),
            Err(ERROR_PIPE_NOT_CONNECTED),
            Err(ERROR_FILE_NOT_FOUND),
            Ok(()),
        ]);
        let calls = std::cell::Cell::new(0u32);
        let result = connect_with_retry(
            || {
                calls.set(calls.get() + 1);
                script.pop_front().unwrap_or(Err(ERROR_FILE_NOT_FOUND))
            },
            || true,
        );
        assert!(result.is_ok(), "瞬态错误序列后必须连接成功");
        let calls = calls.get();
        assert!(
            calls <= CONNECT_TRANSIENT_RETRIES + 1,
            "重试次数不得超过上限 {CONNECT_TRANSIENT_RETRIES}，实际 {calls}"
        );
    }

    /// 持续瞬态失败 → 必须报错且总时长有界（规格：不无限阻塞 CLI）。
    #[test]
    fn persistent_transient_errors_fail_within_bounded_time() {
        let start = std::time::Instant::now();
        let calls = std::cell::Cell::new(0u32);
        let result = connect_with_retry(
            || {
                calls.set(calls.get() + 1);
                Err::<(), u32>(ERROR_FILE_NOT_FOUND)
            },
            || true,
        );
        assert!(result.is_err(), "持续失败必须报错");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "总时长必须有界，实际 {:?}",
            start.elapsed()
        );
        assert!(
            calls.get() <= CONNECT_TRANSIENT_RETRIES + 1,
            "调用次数必须有界，实际 {}",
            calls.get()
        );
    }

    /// 非瞬态错误（如 ACCESS_DENIED）→ 不重试、立即上抛（既有语义）。
    #[test]
    fn non_transient_error_fails_immediately() {
        let calls = std::cell::Cell::new(0u32);
        let result = connect_with_retry(
            || {
                calls.set(calls.get() + 1);
                Err::<(), u32>(5) // ERROR_ACCESS_DENIED
            },
            || true,
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 1, "非瞬态错误不得重试");
    }

    /// BUSY → wait_busy 成功后继续（既有语义保持不变）。
    #[test]
    fn busy_error_waits_then_retries() {
        let mut script = std::collections::VecDeque::from(vec![Err(ERROR_PIPE_BUSY), Ok(())]);
        let waited = std::cell::Cell::new(false);
        let result = connect_with_retry(
            || script.pop_front().unwrap_or(Err(ERROR_PIPE_BUSY)),
            || {
                waited.set(true);
                true
            },
        );
        assert!(result.is_ok());
        assert!(waited.get(), "BUSY 必须先走 WaitNamedPipeW 语义");
    }

    // -------------------------------------------------------------------------
    // seam C「响应送达后再断连」（FlushFileBuffers）：Linux 无法真实观察
    // Windows 管道刷盘顺序，不硬造实现耦合测试——以下 windows-only 回归锁
    // 仅在 Windows 测试跑中执行，Linux 上只做 windows-gnu 类型检查。
    // -------------------------------------------------------------------------

    /// 测试进程内 mock 守护共用的停机旗标（永不置位——测试进程退出即随之
    /// 消亡）。
    #[cfg(windows)]
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);

    /// 慢读客户端回归锁：服务端写完响应后不得在客户端读走之前断连——旧实现
    /// 写完 ~37µs 即 `DisconnectNamedPipe`，管道缓冲区内响应随断连被系统丢弃，
    /// 延迟读的客户端拿到截断响应（UnexpectedEof → probe 放大成误杀）。修复后
    /// 服务端断连前先 `FlushFileBuffers`（阻塞至客户端读走全部已写数据），故
    /// 此处刻意延迟 150ms 再读仍必须拿到完整响应。
    ///
    /// TODO(CI): 本测试仅在 Windows 测试跑中实际执行；需 CI windows-latest 或
    /// 真机 E2E 复测确认响应丢失率归零。
    #[cfg(windows)]
    #[test]
    fn response_delivered_before_disconnect_slow_reader_still_gets_frame() {
        let tmp = tempfile::tempdir().unwrap();
        bind_server(tmp.path()).expect("bind mock server");
        let handler: Handler = Arc::new(|line, _| serde_json::json!({ "echo": line }).to_string());
        {
            let dir = tmp.path().to_path_buf();
            std::thread::spawn(move || {
                let _ = serve(&dir, handler, None, &SHUTDOWN);
            });
        }
        // serve 线程需要一点时间创建首个监听实例；connect() 自带瞬态短重试
        let mut ep = None;
        for _ in 0..20 {
            if let Some(e) = read_endpoint(tmp.path()) {
                ep = Some(e);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let ep = ep.expect("daemon.json 已写入");

        let mut stream = connect(&ep).expect("连接 mock 守护");
        write_line(
            &mut stream,
            r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{}}"#,
        )
        .unwrap();
        // 刻意慢读：旧实现在此窗口内已断连丢帧 → 本行报 UnexpectedEof
        std::thread::sleep(Duration::from_millis(150));
        let resp = read_line(&mut stream)
            .expect("响应必须在服务端断连前仍可完整读出")
            .expect("连接未提前 EOF");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("响应为合法 JSON");
        let echo: serde_json::Value =
            serde_json::from_str(v["echo"].as_str().expect("回显原始帧")).expect("回显为合法 JSON");
        assert_eq!(echo["id"], 1, "慢读客户端必须拿到完整回显响应");
    }
}
