fn main() {
    capnpc::CompilerCommand::new()
        .file("schema/wirken.capnp")
        .run()
        .expect("capnp schema compilation failed");
}
