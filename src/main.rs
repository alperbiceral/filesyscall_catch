// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

use anyhow::{bail, Result};
use libbpf_rs::{skel::{OpenSkel, SkelBuilder}, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter, BufRead, BufReader};
use std::ffi::CStr;
use std::ptr;
use libc::{time_t, tm, localtime, strftime, time};

mod ebpf {
    include!(concat!(env!("OUT_DIR"), "/ebpf.skel.rs"));
}

use ebpf::*;

// definition of the event structure in the BPF program
#[repr(C)]
#[derive(Debug)]
struct EventInfo {
    pid: u32,
    function_name: [u8; 64],
    filename: [u8; 128],
    line_no: i32,
    syscall_id: i32,
    arg0: [u8; 256],
    arg1: [u8; 256],
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
    if ret != 0 {
        bail!("Failed to increase rlimit");
    }
    Ok(())
}

// Function to resolve fd to actual file path
fn resolve_fd_to_path(pid: u32, fd: &str) -> String {
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    
    match std::fs::read_link(&proc_path) {
        Ok(target) => {
            if let Some(path_str) = target.to_str() {
                path_str.to_string()
            } else {
                format!("fd:{}", fd)
            }
        },
        Err(_) => {
            // Fallback for common fds
            match fd {
                "0" => "stdin".to_string(),
                "1" => "stdout".to_string(),
                "2" => "stderr".to_string(),
                _ => format!("fd:{}", fd)
            }
        }
    }
}

// This is used to clean up file paths that may have been prefixed with "fd:"
fn strip_slash(s: &str) -> &str {
    if let Some(idx) = s.find("//") {
        &s[idx + 2..]
    } else if let Some(idx) = s.find('/') {
        &s[idx + 1..]
    }
    else {
        s
    }
}

// Callback function to handle ring buffer events
fn handle_event(data: &[u8], writer: &mut BufWriter<std::fs::File>) -> i32 {
    if data.len() != std::mem::size_of::<EventInfo>() {
        writeln!(writer, "Invalid event size: {} bytes", data.len()).ok();
        writer.flush().ok();
        return 1;
    }

    // Cast the data to our event structure
    let event = unsafe { &*(data.as_ptr() as *const EventInfo) };

    // Convert C strings to Rust strings
    let function_name = std::ffi::CStr::from_bytes_until_nul(&event.function_name)
        .unwrap_or_default()
        .to_string_lossy();
    
    let filename = std::ffi::CStr::from_bytes_until_nul(&event.filename)
        .unwrap_or_default()
        .to_string_lossy();

    let arg0 = std::ffi::CStr::from_bytes_until_nul(&event.arg0)
        .unwrap_or_default()
        .to_string_lossy();

    let arg1 = std::ffi::CStr::from_bytes_until_nul(&event.arg1)
        .unwrap_or_default()
        .to_string_lossy();

    match event.syscall_id {
        0 => { // read
            let target = resolve_fd_to_path(event.pid, &arg0);
            writeln!(writer, "READ: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        1 => { // write
            let target = resolve_fd_to_path(event.pid, &arg0);
            writeln!(writer, "WRITE: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        2 => { // open
            writeln!(writer, "OPEN: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, arg0).ok();
        },
        82 => { // rename
            writeln!(writer, "RENAME: PID {} in {}() [{}:{}] - Old Path: {}, New Path: {}", 
                    event.pid, function_name, filename, event.line_no, arg0, arg1).ok();
        },
        83 => { // mkdir
            writeln!(writer, "MKDIR: PID {} in {}() [{}:{}] - Target Directory: {}", 
                    event.pid, function_name, filename, event.line_no, arg0).ok();
        },
        90 => { // chmod
            writeln!(writer, "CHMOD: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, arg0).ok();
        },
        91 => { // fchmod
            let target = resolve_fd_to_path(event.pid, &arg0);
            writeln!(writer, "FCHMOD: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        257 => { // openat
            let mut target = resolve_fd_to_path(event.pid, &arg0);
            target += &format!("/{}", arg1);
            target = strip_slash(&target).to_string();
            writeln!(writer, "OPENAT: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        258 => { // mkdirat
            writeln!(writer, "MKDIRAT: PID {} in {}() [{}:{}] - Target Directory: {}",
                    event.pid, function_name, filename, event.line_no, arg0).ok();
        },
        262 => { // newfstatat
            let mut target = resolve_fd_to_path(event.pid, &arg0);
            target += &format!("/{}", arg1);
            target = strip_slash(&target).to_string();
            writeln!(writer, "NEWFSTATAT: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        263 => { // unlinkat
            let mut target = resolve_fd_to_path(event.pid, &arg0);
            target += &format!("/{}", arg1);
            target = strip_slash(&target).to_string();
            writeln!(writer, "UNLINKAT: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        268 => { // fchmodat
            let mut target = resolve_fd_to_path(event.pid, &arg0);
            target += &format!("/{}", arg1);
            target = strip_slash(&target).to_string();
            writeln!(writer, "FCHMODAT: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        437 => { // openat2
            let mut target = resolve_fd_to_path(event.pid, &arg0);
            target += &format!("/{}", arg1);
            target = strip_slash(&target).to_string();
            writeln!(writer, "OPENAT2: PID {} in {}() [{}:{}] - Target File: {}", 
                    event.pid, function_name, filename, event.line_no, target).ok();
        },
        _ => {
            writeln!(writer, "SYSCALL ID {}: PID {} in {}() [{}:{}]", 
                    event.syscall_id, event.pid, function_name, filename, event.line_no).ok();
        }
    }
    writer.flush().ok();
    0 // Return 0 for success
}

#[tokio::main]
async fn main() -> Result<()> {
    // Increase RLIMIT_MEMLOCK to allow BPF programs to use more memory
    bump_memlock_rlimit()?;

    // Create output file with timestamp using libc/strftime as in the example
    let mut output_file = None;
    let mut filename = None;
    unsafe {
        let mut t: time_t = time(ptr::null_mut());
        let tm: *mut tm = localtime(&mut t);
        let mut buf = [0u8; 64];
        // Format: output_day_month-hour_minute.txt
        strftime(
            buf.as_mut_ptr() as *mut i8,
            buf.len(),
            b"%d_%m-%H_%M\0".as_ptr() as *const i8,
            tm,
        );
        let cstr = CStr::from_ptr(buf.as_ptr() as *const i8);
        filename = Some(format!("output_{}.txt", cstr.to_str().unwrap()));
        output_file = Some(OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename.clone().unwrap())?);
    }
    let mut writer = BufWriter::new(output_file.unwrap());

    // Build and open the BPF skeleton
    let skel_builder = EbpfSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    
    // Load the BPF program
    let mut skel = open_skel.load()?;

    println!("BPF program loaded successfully!");

    // Attach to the read tracepoint
    let _read_entry_link = skel
        .progs_mut()
        .trace_read()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_read probe!");

    // Attach to the write tracepoint
    let _write_entry_link = skel
        .progs_mut()
        .trace_write()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_write probe!");

    // Attach to the newfstatat tracepoint
    let _stat_entry_link = skel
        .progs_mut()
        .trace_newfstatat()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_newfstatat probe!");

    // Attach to the mkdir tracepoint
    let _mkdir_entry_link = skel
        .progs_mut()
        .trace_mkdir()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_mkdir probe!");

    // Attach to the mkdirat tracepoint
    let _mkdirat_entry_link = skel
        .progs_mut()
        .trace_mkdirat()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_mkdirat probe!");

    // Attach to the unlinkat tracepoint
    let _unlinkat_entry_link = skel
        .progs_mut()
        .trace_unlinkat()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_unlinkat probe!");

    // Attach to the open tracepoint
    let _open_entry_link = skel
        .progs_mut()
        .trace_open()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_open probe!");

    // Attach to the openat tracepoint
    let _openat_entry_link = skel
        .progs_mut()
        .trace_openat()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_openat probe!");

    // Attach to the openat2 tracepoint
    let _openat2_entry_link = skel
        .progs_mut()
        .trace_openat2()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_openat2 probe!");

    // Attach to the chmod tracepoint
    let _chmod_entry_link = skel
        .progs_mut()
        .trace_chmod()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_chmod probe!");

    // Attach to the fchmod tracepoint
    let _fchmod_entry_link = skel
        .progs_mut()
        .trace_fchmod()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_fchmod probe!");

    // Attach to the fchmodat tracepoint
    let _fchmod_entry_link = skel
        .progs_mut()
        .trace_fchmodat()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_fchmodat probe!");

    // Attach to the rename tracepoint
    let _rename_entry_link = skel
        .progs_mut()
        .trace_rename()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_rename probe!");

    // Attach to the execve tracepoint
    let _execve_entry_link = skel
        .progs_mut()
        .trace_execve()
        .attach()?;

    println!("Successfully attached to tracepoint sys_enter_execve probe!");

    // Attach to PHP USDT probe
    let _link = skel
        .progs_mut()
        .trace_php_function_entry()
        .attach_usdt(
            -1,  // Attach to all processes
            "/usr/local/bin/php-dtrace",
            "php",
            "function__entry",
        )?;

    println!("Successfully attached to PHP function__entry probe!");

    let _return_link = skel
        .progs_mut()
        .trace_php_function_return()
        .attach_usdt(
            -1,  // Attach to all processes
            "/usr/local/bin/php-dtrace",
            "php",
            "function__return",
        )?;

    println!("Successfully attached to PHP function__return probe!");

    // Set up ring buffer - do this all in one go to avoid lifetime issues
    let ring_buffer = {
        let maps = skel.maps();
        let events_map = maps.events();
        let mut builder = RingBufferBuilder::new();
        // pass a closure that captures &mut writer
        let writer_ptr = &mut writer as *mut _;
        builder.add(events_map, move |data: &[u8]| {
            // SAFETY: writer_ptr is valid for the lifetime of main
            let writer = unsafe { &mut *writer_ptr };
            handle_event(data, writer)
        })?;
        builder.build()?
    };

    println!("Ring buffer set up successfully!");

    println!("Monitor kernel trace (for debugging) with:");
    println!("  sudo cat /sys/kernel/tracing/trace_pipe");
    println!("Output file: {}", filename.clone().unwrap());
    println!("Press Ctrl+C to stop...\n");

    // Set up signal handling
    let exiting = Arc::new(AtomicBool::new(false));
    let exiting_clone = exiting.clone();
    
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        exiting_clone.store(true, Ordering::SeqCst);
    });

    // Keep the program running
    while !exiting.load(Ordering::SeqCst) {
        // Poll the ring buffer for events
        match ring_buffer.poll(Duration::from_millis(100)) {
            Ok(_) => {
                // Events processed by handle_event callback
            }
            Err(e) => {
                eprintln!("Error polling ring buffer: {}", e);
                break;
            }
        }
    }

    println!("\nDetaching probes and exiting...");
    Ok(())
}