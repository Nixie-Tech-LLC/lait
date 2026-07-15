//! Spawning the daemon without handing it anything else of ours.
//!
//! The daemon outlives the command that spawns it, so every handle it comes up
//! holding, it holds *for its whole life*. On unix that is already true by
//! construction: fds are `CLOSE_ON_EXEC`, so the child starts with nothing but
//! the three `Stdio` slots we named. Windows has no such default —
//! `CreateProcess` takes a single `bInheritHandles` switch, and `TRUE` means
//! *every* inheritable handle in this process, not just the ones in
//! `STARTUPINFO`. A daemon spawned from a captured `lait new` therefore came up
//! owning a write-end of that command's stdout, and the command's caller waited
//! forever on an EOF that could not arrive (see `app::disinherit_stdio`, which
//! covers our *own* stdio — this module covers everything else, including the
//! handles we inherited from our parent and never knew about).
//!
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` is the only way to say "inherit exactly
//! these" — so the Windows path drives `CreateProcessW` itself. std exposes the
//! same attribute only under an unstable feature (rust#114854) and this crate is
//! pinned to stable, so there is no std route to it today. If that stabilises,
//! this module collapses back into a `Command` builder.

use std::io;
use std::path::Path;
use std::process::ExitStatus;

/// A spawned daemon. Only what `ensure_daemon` needs: is it still alive?
pub struct DaemonChild {
    #[cfg(windows)]
    proc: std::os::windows::io::OwnedHandle,
    #[cfg(not(windows))]
    child: std::process::Child,
}

/// Spawn `<exe> daemon` bound to `home`, with `log` (when present) as its stderr
/// and `NUL`/`/dev/null` for the rest.
///
/// `log` is the daemon's own diagnosis when a spawn fails ("another lait daemon
/// is already running for this home…"), which is the whole error message on that
/// path — so it is a real file, not a null sink.
pub fn spawn(exe: &Path, home: &Path, log: Option<std::fs::File>) -> io::Result<DaemonChild> {
    imp::spawn(exe, home, log)
}

impl DaemonChild {
    /// `Some(status)` once the daemon has exited, `None` while it is running.
    ///
    /// A daemon that has already exited is never going to answer, so the spawn
    /// wait polls this to fail fast with its own words instead of blaming a 20s
    /// timeout.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        imp::try_wait(self)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::process::{Command, Stdio};

    pub fn spawn(exe: &Path, home: &Path, log: Option<std::fs::File>) -> io::Result<DaemonChild> {
        let stderr = match log {
            Some(f) => Stdio::from(f),
            None => Stdio::null(),
        };
        // Pin the resolved store for the spawned daemon so it binds the exact
        // same store regardless of its cwd (DUR-5). `LAIT_HOME`, when set
        // (self-contained / --home / resume), is inherited from our env and
        // takes precedence, so this is a no-op in that mode.
        let child = Command::new(exe)
            .arg("daemon")
            .env("LAIT_STORE", home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()?;
        Ok(DaemonChild { child })
    }

    pub fn try_wait(c: &mut DaemonChild) -> io::Result<Option<ExitStatus>> {
        c.child.try_wait()
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::{c_void, OsStr};
    use std::fs::{File, OpenOptions};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::os::windows::process::ExitStatusExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// A handle named in the inherit list must itself be inheritable — the list
    /// narrows what crosses, it does not mark anything.
    fn make_inheritable(f: &File) -> io::Result<HANDLE> {
        let h = f.as_raw_handle() as HANDLE;
        // SAFETY: `h` is the live handle of a `File` we own and hold borrowed.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(h)
    }

    fn nul(write: bool) -> io::Result<File> {
        if write {
            OpenOptions::new().write(true).open("NUL")
        } else {
            OpenOptions::new().read(true).open("NUL")
        }
    }

    /// Frees the attribute list on every exit path, including the error ones.
    struct AttrList(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttrList {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a list we successfully initialised, freed once.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }

    pub fn spawn(exe: &Path, home: &Path, log: Option<std::fs::File>) -> io::Result<DaemonChild> {
        // Pin the resolved store for the spawned daemon so it binds the exact
        // same store regardless of its cwd (DUR-5). Set on *our* env rather than
        // a child-only override, so the daemon can inherit our block wholesale
        // (`lpEnvironment` = NULL) and we never hand-build one: Windows requires
        // the block sorted case-insensitively, and letting the OS keep that
        // invariant is worth more than avoiding one process-wide set_var — which
        // is how `-w` already pins the store anyway (see `app::dispatch`).
        // `LAIT_HOME`, when set, is read first, so this is a no-op in that mode.
        std::env::set_var("LAIT_STORE", home);

        // Held to the end of the call: these must outlive `CreateProcessW`, which
        // duplicates them into the child. Our copies close on drop.
        let stdin = nul(false)?;
        let stdout = nul(true)?;
        let stderr = match log {
            Some(f) => f,
            None => nul(true)?,
        };
        let handles: [HANDLE; 3] = [
            make_inheritable(&stdin)?,
            make_inheritable(&stdout)?,
            make_inheritable(&stderr)?,
        ];

        // Sized by the API, then allocated as `usize` words: an attribute list is
        // pointer-aligned, which a `Vec<u8>` would not guarantee.
        let mut size = 0usize;
        // SAFETY: the sizing call. It always "fails" (ERROR_INSUFFICIENT_BUFFER)
        // and writes the required size, which is the only reason we call it.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let words = size.div_ceil(std::mem::size_of::<usize>()).max(1);
        let mut buf: Vec<usize> = vec![0; words];
        let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: `list` points to `size` bytes of pointer-aligned storage.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let list = AttrList(list);

        // The whole point: the child inherits these three handles and nothing
        // else, whatever else of ours happens to be inheritable.
        // SAFETY: `handles` outlives the `CreateProcessW` call below, as the API
        // requires (the list borrows it rather than copying).
        if unsafe {
            UpdateProcThreadAttribute(
                list.0,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *const c_void,
                std::mem::size_of_val(&handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = handles[0];
        si.StartupInfo.hStdOutput = handles[1];
        si.StartupInfo.hStdError = handles[2];
        si.lpAttributeList = list.0;

        let app = wide(exe.as_os_str());
        // `CreateProcessW` may write to the command line buffer, so it is ours and
        // mutable. Quoted because a path with a space would otherwise split; a
        // Windows path cannot contain `"`, so there is nothing else to escape.
        let mut cmdline = wide(OsStr::new(&format!("\"{}\" daemon", exe.display())));

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is valid for the call. `bInheritHandles` must be
        // TRUE for the attribute list to be consulted at all — it is what the
        // list narrows.
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful CreateProcessW hands us both handles. We never use
        // the thread; the process handle becomes ours to own.
        unsafe { CloseHandle(pi.hThread) };
        let proc = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) };
        Ok(DaemonChild { proc })
    }

    pub fn try_wait(c: &mut DaemonChild) -> io::Result<Option<ExitStatus>> {
        let h = c.proc.as_raw_handle() as HANDLE;
        // A zero timeout is the poll. Asking the process object rather than
        // reading the exit code first: 259 is both STILL_ACTIVE and a legal exit
        // code, so the code alone cannot tell them apart.
        // SAFETY: `h` is the live process handle we own.
        match unsafe { WaitForSingleObject(h, 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: as above; the process has exited, so the code is final.
                if unsafe { GetExitCodeProcess(h, &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(ExitStatus::from_raw(code)))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
