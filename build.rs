// Compile bpf/rgmond.bpf.c with clang into an object the binary embeds.
use std::process::Command;

fn main() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("rgmond.bpf.o");
    println!("cargo:rerun-if-changed=bpf/rgmond.bpf.c");
    let st = Command::new("clang")
        .args(["-O2", "-target", "bpf", "-D__TARGET_ARCH_x86", "-Wall", "-Werror", "-c", "bpf/rgmond.bpf.c", "-o"])
        .arg(&out)
        .status()
        .expect("running clang (needed to build the BPF programs)");
    assert!(st.success(), "clang failed to compile bpf/rgmond.bpf.c");
}
