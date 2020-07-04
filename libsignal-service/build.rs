use std::path::Path;

fn main() {
    let protobuf = Path::new("protobuf").to_owned();

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

    prost_build::compile_protos(&input, &[protobuf]).unwrap();
}
