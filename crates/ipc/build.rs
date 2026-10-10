fn main() {
    // The schema is the build script's only input. Naming it keeps cargo
    // from rerunning the script, and rebuilding every crate that uses
    // this one, whenever any other file in the package changes.
    println!("cargo:rerun-if-changed=schema/wirken.capnp");
    capnpc::CompilerCommand::new()
        .file("schema/wirken.capnp")
        .run()
        .expect("capnp schema compilation failed");
}
