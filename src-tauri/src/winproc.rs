//! 直接调 Win32 API 做「按端口找监听进程 / 结束进程 / 查映像名」。
//!
//! 为什么不 shell 出 `tasklist` / `taskkill`：这两个工具依赖 WMI 命名空间，
//! 在 WMI 损坏的机器上会立刻以 `错误: 无效命名空间` 退出（rc=1、无输出），
//! 于是「停止服务」会静默失败——本机就是这种状态，实测两个工具都不可用。
//! 进程内直接调 APIs 没有这个依赖，也不受 PATH、本地化输出格式的影响。
//!
//! 只处理 IPv4：反代服务默认绑 `127.0.0.1`，桌面端探测的也是 IPv4 回环。

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

/// IPHLPAPI 的「缓冲区太小」错误码，表示它已经把所需大小写回了 `size`。
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// 找出本机所有正在监听 `port` 的进程号。
///
/// 返回空 `Vec` 表示「没人监听」，或查询本身失败——调用方拿不到区别也没关系，
/// 因为后续判断统一以「端口还能不能连上」为准。
pub fn listening_pids(port: u16) -> Vec<u32> {
    let mut size: u32 = 0;
    // 第一次只问大小：缓冲区传空，期望拿回 ERROR_INSUFFICIENT_BUFFER。
    let probe = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            FALSE,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if probe != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return Vec::new();
    }

    // 表是按 4 字节对齐的，`Vec<u32>` 天然满足；长度多留一点余量，
    // 免得两次调用之间连接表又长了一行。
    let words = (size as usize).div_ceil(4) + 64;
    let mut buffer = vec![0u32; words];
    let code = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            FALSE,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if code != 0 {
        return Vec::new();
    }

    // 布局：dwNumEntries 紧跟着一个 MIB_TCPROW_OWNER_PID 数组。
    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let entries = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::ptr::addr_of!((*table).table) as *const MIB_TCPTABLE_OWNER_PID }
        .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID>();

    let mut found = Vec::new();
    for index in 0..entries {
        let row = unsafe { &*rows.add(index) };
        // `TCP_TABLE_OWNER_PID_LISTENER` 本身已经只返回监听中的 socket，无需再按
        // `dwState` 过滤。部分 Windows 上这张表里的监听项 `dwState` 是 0 而不是
        // `MIB_TCP_STATE_LISTEN`(2)，再过滤会让 `listening_pids` 永远为空，
        // 于是「停止服务」按端口反查不到监听者（外部启动/Onefile 子进程都会失败）。
        // dwLocalPort 是网络字节序，低 16 位里是高字节在前。
        let local = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        if local != port {
            continue;
        }
        let pid = row.dwOwningPid;
        if pid != 0 && !found.contains(&pid) {
            found.push(pid);
        }
    }
    found
}

/// 取进程映像的完整路径（如 `C:\...\wb-reverse-proxy.exe`）。
pub fn image_path_of(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if handle == 0 {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some(OsString::from_wide(&buf[..len as usize]).to_string_lossy().into_owned())
}

/// 取进程映像的文件名（如 `wb-reverse-proxy.exe`）。
pub fn image_name_of(pid: u32) -> Option<String> {
    let path = image_path_of(pid)?;
    Some(
        std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or(path),
    )
}

/// 结束单个进程。失败时把原因（含 Win32 错误码）带回来，好判断是不是权限问题。
pub fn terminate(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, FALSE, pid) };
    if handle == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!("打不开进程 {pid}（Win32 错误 {code}）"));
    }
    let ok = unsafe { TerminateProcess(handle, 1) };
    let code = unsafe { GetLastError() };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(format!("结束进程 {pid} 失败（Win32 错误 {code}）"));
    }
    Ok(())
}

/// 以管理员身份重新拉起自己，去结束指定进程（UAC 会弹确认框）。
///
/// 走「自己的 exe + `--stop-pid=`」而不是 `taskkill`：一是 taskkill 在部分机器上
/// 根本不可用（见模块头注释），二是这样不需要假设目标机上有什么工具。
#[cfg(windows)]
pub fn elevate_stop_pid(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe().map_err(|error| format!("取当前程序路径失败：{error}"))?;
    let exe: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let params: Vec<u16> = format!("--stop-pid={pid}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // 返回值 > 32 才算成功（ShellExecute 的历史约定）。
    let result = unsafe {
        ShellExecuteW(
            0, // 无父窗口（HWND 在 windows-sys 里就是 isize）
            verb.as_ptr(),
            exe.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(format!(
            "提权启动失败（ShellExecute 返回 {result:?}）。若在 UAC 里点了「否」，请重试并允许。"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真开一个回环监听，验证 GetExtendedTcpTable 能把我们自己查出来。
    /// 这条是「停止服务」赖以工作的核心能力，必须真跑一次。
    #[test]
    fn finds_our_own_listening_pid() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定回环端口");
        let port = listener.local_addr().expect("取本地地址").port();
        let pids = listening_pids(port);
        assert!(
            pids.contains(&std::process::id()),
            "应查出自己（pid {}）在监听 {port}，实际得到 {pids:?}",
            std::process::id()
        );
    }

    #[test]
    fn free_port_has_no_listener() {
        // 绑一下就放掉，拿到的端口必然没人监听。
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定回环端口");
            listener.local_addr().expect("取本地地址").port()
        };
        assert!(listening_pids(port).is_empty(), "端口 {port} 不该有监听者");
    }

    #[test]
    fn reads_own_image_name() {
        let name = image_name_of(std::process::id()).expect("应能读到自己的映像名");
        assert!(name.to_lowercase().ends_with(".exe"), "实际读到 {name}");
        // 完整路径版本要包含文件名。
        let path = image_path_of(std::process::id()).expect("应能读到自己的映像路径");
        assert!(path.contains(&name), "路径 {path} 里应含 {name}");
    }

    #[test]
    fn refuses_pid_windows_will_not_open() {
        // pid 0 是「系统空闲进程」，OpenProcess 必然失败——错误信息要带回来而不是 panic。
        let error = terminate(0).expect_err("pid 0 不该被允许结束");
        assert!(error.contains("Win32 错误"), "错误信息应含 Win32 错误码：{error}");
    }
}
