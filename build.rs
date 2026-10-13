fn main() {
    #[cfg(feature = "gpu-ref")]
    {
        println!("cargo:rerun-if-changed=gpu/kernel.metal");
        println!("cargo:rerun-if-changed=gpu/cpu_ref.cpp");
        cc::Build::new()
            .cpp(true)
            .file("gpu/cpu_ref.cpp")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-Wno-unknown-attributes")
            .opt_level(3)
            .compile("plcmint_gpu_ref");
    }
}
