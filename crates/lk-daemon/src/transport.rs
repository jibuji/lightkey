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
//!   访问自动拉起守护进程（检测到陈旧端点 → 先杀旧进程再拉起）。
//!   `version` 供协议版本校验（cross-subsystem.md §7.3），旧文件缺省可读。

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
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, TerminateProcess};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const ERROR_PIPE_BUSY: u32 = 231;
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

    /// 监听并处理连接（每连接一线程；订阅连接转流模式）。
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
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
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
                return Err(std::io::Error::last_os_error());
            }
            let ok = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                unsafe {
                    CloseHandle(handle);
                }
                continue;
            }
            let handler = handler.clone();
            let hub = hub.clone();
            let peer = peer_info(handle);
            let sh = SendHandle(handle);
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
                unsafe {
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

    /// 客户端连接（pipe 忙则等待；不存在视为守护进程未运行）。
    pub fn connect(ep: &Endpoint) -> std::io::Result<PipeStream> {
        let name = wide(&ep.address);
        loop {
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
                return Ok(PipeStream {
                    handle: SendHandle(handle),
                });
            }
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                let ok = unsafe { WaitNamedPipeW(name.as_ptr(), 10_000) };
                if ok == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                continue;
            }
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
    }

    pub fn pid_alive(pid: u32) -> bool {
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h == INVALID_HANDLE_VALUE {
            return false;
        }
        unsafe {
            CloseHandle(h);
        }
        true
    }

    pub fn kill_pid(pid: u32) {
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h != INVALID_HANDLE_VALUE {
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

/// 确保守护进程在跑：探测端点 → 陈旧则杀旧 → 拉起 → 等待就绪。
/// `dir_override` 为 `lk --dir` 的显式值（透传给子进程）。
pub fn ensure_daemon(dir: &Path) -> std::io::Result<Endpoint> {
    if let Some(ep) = read_endpoint(dir) {
        if probe(&ep) {
            return Ok(ep);
        }
        // 陈旧端点：先杀旧进程再清理
        if pid_alive(ep.pid) {
            kill_pid(ep.pid);
        }
        cleanup(dir, &ep);
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
}
