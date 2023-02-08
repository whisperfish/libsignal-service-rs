use std::path::Path;

fn main() {
    let protobuf = Path::new("protobuf").to_owned();

    // Build script does not automagically rerun when a new protobuf file is added.
    // Directories are checked against mtime, which is platform specific
    println!("cargo:rerun-if-changed=protobuf");
    // Adding src/proto.rs means an extra `include!` will trigger a rerun. This is on best-effort
    // basis.
    println!("cargo:rerun-if-changed=src/proto.rs");

    let input: Vec<_> = protobuf
        .read_dir()
        .expect("protobuf directory")
        .filter_map(|entry| {
            let entry = entry.expect("readable protobuf directory");
            let path = entry.path();
            if Some("proto")
                == path.extension().and_then(std::ffi::OsStr::to_str)
            {
                assert!(path.is_file());
                println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
                Some(path)
            } else {
                None
            }
        })
        .collect();

    let mut prost_build = prost_build::Config::new();
    prost_build
        .default_package_filename("signal")
        .compile_protos(&input, &[protobuf])
        .unwrap();
}
