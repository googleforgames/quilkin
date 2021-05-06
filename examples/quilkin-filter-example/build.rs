fn main() {
    prost_build::compile_protos(&["src/greet.proto"], &["src/"]).unwrap();
}
