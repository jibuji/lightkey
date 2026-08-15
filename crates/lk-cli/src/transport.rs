//! 本地 IPC 传输层（规格：`docs/ipc.md` §2/§6）。
//!
//! - Unix domain socket（macOS/Linux，0600）/ Windows named pipe（仅本用户，
//!   随机 pipe 名 + 用户私有数据目录）。
//! - 帧：单行 JSON（`\n` 结尾），客户端一请求一响应。
//! - **socket/pipe 路径含用户级随机组件**，且位于用户私有数据目录
//!   （0700）——防跨用户劫持。
//! - 守护进程信息（pid + 端点）写入 `daemon.json`；客户端首次访问自动拉起
//!   守护进程（检测到陈旧端点 → 先杀旧进程再拉起）。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// 守护进程端点信息（数据目录下 `daemon.json`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub pid: u32,
    /// unix: socket 绝对路径；windows: 完整 pipe 名。
    pub address: String,
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

// ---------------------------------------------------------------------------
// Unix domain socket
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

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
        };
        write_endpoint(dir, &ep)?;
        Ok(listener)
    }

    /// 监听并处理连接（每连接一线程，读一行 → handler → 写一行）。
    pub fn serve(
        listener: UnixListener,
        handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
        shutdown: &'static AtomicBool,
    ) -> std::io::Result<()> {
        // 非阻塞 accept + 轮询 shutdown，保证 SIGTERM/SIGINT 能优雅退出
        listener.set_nonblocking(true)?;
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let handler = handler.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(300)));
                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(300)));
                        let mut s = stream;
                        if let Ok(Some(line)) = read_line(&mut s) {
                            let resp = handler(&line);
                            let _ = write_line(&mut s, &resp);
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// 客户端连接。
    pub fn connect(ep: &Endpoint) -> std::io::Result<UnixStream> {
        let stream = UnixStream::connect(&ep.address)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(300)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(300)))?;
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
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess};

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

    /// 生成 pipe 名：`\\.\pipe\lightkey-<user>-<随机8hex>`（用户级随机组件防劫持）。
    pub fn bind(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
        let rand = hex::encode(lk_core::crypto::random_array::<8>());
        let pipe_name = format!("\\\\.\\pipe\\lightkey-{user}-{rand}");
        let ep = Endpoint {
            pid: std::process::id(),
            address: pipe_name,
        };
        write_endpoint(dir, &ep)?;
        Ok(())
    }

    /// 仅限当前用户的 pipe 安全属性（ipc.md §2「pipe ACL」，A2）。
    ///
    /// Windows 默认 DACL 允许同机器任意进程连接；这里显式构建 DACL，
    /// 仅授予当前进程用户 SID 完全访问权（SYSTEM/Administrators 亦不放行），
    /// 配合随机 pipe 名实现「仅本用户可访问」（Linux 侧 UDS 0600 的对应补齐）。
    /// 描述符与 ACL 缓冲随结构体存活，保证 CreateNamedPipeW 调用期间有效。
    struct UserOnlySa {
        attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
        _sd: windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
        _acl: Vec<u8>,
    }

    fn user_only_sa() -> std::io::Result<UserOnlySa> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAce, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
            SetSecurityDescriptorDacl, TokenUser, ACL, ACL_REVISION, PSECURITY_DESCRIPTOR, PSID,
            SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // GENERIC_ALL = 0x1000_0000（SE_FILE_OBJECT 型访问掩码的完全控制）。
        const GENERIC_ALL: u32 = 0x1000_0000;
        // SECURITY_DESCRIPTOR_REVISION = 1（windows-sys 未导出该常量，按文档用字面量）。
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

        unsafe {
            // 1) 当前进程主令牌 → 用户 SID。GetTokenInformation 把 SID 拷贝进
            //    调用方缓冲区（TOKEN_USER.User.Sid 指向缓冲区内的 SID），
            //    令牌句柄用完即可关闭。
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

            // 2) DACL：单条 ACE = 该用户 SID 完全访问（AddAccessAllowedAce
            //    会把 SID 拷贝进 ACL 缓冲区，此后与令牌无关）。
            let mut acl_buf = vec![0u8; 256];
            let acl = acl_buf.as_mut_ptr() as *mut ACL;
            if InitializeAcl(acl, acl_buf.len() as u32, ACL_REVISION) == 0
                || AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            // 3) 自包含安全描述符：DACL 指针指向上面的 ACL 缓冲区。
            let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
            if InitializeSecurityDescriptor(
                &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
                SECURITY_DESCRIPTOR_REVISION,
            ) == 0
                || SetSecurityDescriptorDacl(
                    &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
                    1, /* bDaclPresent */
                    acl,
                    0, /* bDaclDefaulted */
                ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: &mut sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
                bInheritHandle: 0,
            };
            Ok(UserOnlySa {
                attrs,
                _sd: sd,
                _acl: acl_buf,
            })
        }
    }

    /// 监听并处理连接（每连接一线程）。
    pub fn serve(
        _dir: &Path,
        handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
        shutdown: &'static AtomicBool,
    ) -> std::io::Result<()> {
        let ep = read_endpoint(_dir)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "缺少 daemon.json"))?;
        let name = wide(&ep.address);
        // ipc.md §2：named pipe 显式 ACL 仅限当前用户（默认 DACL 放行同机器任意进程）
        let sa = user_only_sa()?;
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
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
            let sh = SendHandle(handle);
            std::thread::spawn(move || {
                let mut stream = PipeStream { handle: sh };
                if let Ok(Some(line)) = read_line(&mut stream) {
                    let resp = handler(&line);
                    let _ = write_line(&mut stream, &resp);
                }
                unsafe {
                    DisconnectNamedPipe(sh.0);
                    CloseHandle(sh.0);
                }
            });
        }
        Ok(())
    }

    /// HANDLE 是裸指针，跨线程移动需要显式 Send（句柄本质是整数，安全）。
    #[derive(Clone, Copy)]
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}

    pub(crate) struct PipeStream {
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

use std::sync::atomic::AtomicBool;

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
    handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
    shutdown: &'static AtomicBool,
) -> std::io::Result<()> {
    imp::serve(listener, handler, shutdown)
}

#[cfg(windows)]
pub fn serve(
    dir: &Path,
    handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
    shutdown: &'static AtomicBool,
) -> std::io::Result<()> {
    imp::serve(dir, handler, shutdown)
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
        std::thread::sleep(std::time::Duration::from_millis(100));
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
