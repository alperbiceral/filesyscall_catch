use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    
    // Get current kernel version
    let kernel_version = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to get kernel version")
        .stdout;
    let kernel_version = String::from_utf8_lossy(&kernel_version).trim().to_string();
    
    libbpf_cargo::SkeletonBuilder::new()
        .source("ebpf/ebpf.bpf.c")
        .clang_args("-I/usr/include")
        .clang_args("-I/usr/include/x86_64-linux-gnu")
        .clang_args(&format!("-I/usr/src/linux-headers-{}/include", kernel_version))
        .clang_args(&format!("-I/usr/src/linux-headers-{}/arch/x86/include", kernel_version))
        .clang_args("-D__TARGET_ARCH_x86")
        .clang_args("--target=bpf")
        .build_and_generate(&out_dir.join("ebpf.skel.rs"))
        .unwrap();
    
    println!("cargo:rerun-if-changed=ebpf/ebpf.bpf.c");
}