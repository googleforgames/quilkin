use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

const VERSION: &str = "0.2.0";

fn install() {
    if let Ok(output) = Command::new("proto-gen").arg("-V").output() {
        if output.status.success() {
            let version =
                std::str::from_utf8(&output.stdout).expect("proto-gen version output was non-utf8");

            if let Some(v) = version.strip_prefix("proto-gen ") {
                if v.trim() == VERSION {
                    return;
                } else {
                    println!("proto-gen version detected as '{v}' which did not match expected version '{VERSION}'");
                }
            }
        } else {
            println!("failed to retrieve proto-gen version");
        }
    } else {
        println!("proto-gen not installed (or not in PATH)");
    }

    // If we're in CI use the precompiled binary
    if std::env::var_os("CI").is_some() {
        if !cfg!(target_os = "linux") {
            panic!("CI running on a non-linux host is not (yet?) supported");
        }

        // Fetch the tarball
        let output = Command::new("curl")
        .args(["-L", "--fail"])
        .arg(format!("https://github.com/EmbarkStudios/proto-gen/releases/download/v{VERSION}/proto-gen-v{VERSION}-x86_64-unknown-linux-musl.tar.gz"))
        .stdout(Stdio::piped())
        .spawn()
        .expect("curl is not installed")
        .wait_with_output().expect("curl was killed with a signal");

        if !output.status.success() {
            panic!("curl failed with {:?}", output.status);
        } else if output.stdout.len() < 1024 * 1024 {
            panic!(
                "the binary data for the tarball is less than expected: {}b",
                output.stdout.len()
            );
        }

        // Determine the appropriate cargo/bin directory to place the binary in
        let mut cargo_root = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").expect("failed to locate CARGO_HOME or HOME");
                let mut home = PathBuf::from(home);
                home.push(".cargo");
                home
            });

        cargo_root.push("bin");

        // Untar just the binary to CARGO_HOME/bin
        if !Command::new("tar")
            .args(["xzf", "-", "--strip-components=1", "-C"])
            .arg(cargo_root)
            .arg(format!(
                "proto-gen-v{VERSION}-x86_64-unknown-linux-musl/proto-gen"
            ))
            .status()
            .expect("tar is not installed")
            .success()
        {
            panic!("failed to extract proto-gen binary from tarball");
        }
    } else {
        if !Command::new("cargo")
            .args(["install", "-f", "proto-gen"])
            .status()
            .expect("cargo not installed")
            .success()
        {
            panic!("failed to install proto-gen via cargo");
        }
    }
}

fn execute(which: &str) {
    let files: &[(&str, &[&str])] = &[
        (
            "proto/data-plane-api",
            &[
                "envoy/config/accesslog/v3/accesslog",
                // "envoy/config/cluster/v3/cluster",
                // "envoy/config/common/matcher/v3/matcher",
                "envoy/config/listener/v3/listener",
                "envoy/config/listener/v3/listener_components",
                // "envoy/config/route/v3/route",
                // "envoy/service/cluster/v3/cds",
                "envoy/service/discovery/v3/ads",
                "envoy/service/discovery/v3/discovery",
                "envoy/config/endpoint/v3/endpoint_components",
                // "envoy/type/metadata/v3/metadata",
                // "envoy/type/tracing/v3/custom_tag",
            ],
        ),
        ("proto/udpa", &["xds/core/v3/resource_name"]),
        ("proto/google_apis", &[]),
        // For google/protobuf
        ("proto", &[]),
        ("proto/protoc-gen-validate", &[]),
        (
            "proto/quilkin",
            &[
                "relay/v1alpha1/relay",
                "config/v1alpha1/config",
                "filters/capture/v1alpha1/capture",
                "filters/compress/v1alpha1/compress",
                "filters/concatenate/v1alpha1/concatenate",
                "filters/debug/v1alpha1/debug",
                "filters/drop/v1alpha1/drop",
                "filters/firewall/v1alpha1/firewall",
                "filters/load_balancer/v1alpha1/load_balancer",
                "filters/local_rate_limit/v1alpha1/local_rate_limit",
                "filters/match/v1alpha1/match",
                "filters/pass/v1alpha1/pass",
                "filters/token_router/v1alpha1/token_router",
                "filters/timestamp/v1alpha1/timestamp",
            ],
        ),
    ];

    let mut cmd = Command::new("proto-gen");

    cmd
        // Run rustfmt on the output, since they're committed they might as well be nice
        //.arg("--format")
        .arg("-s")
        .arg("-c")
        .arg(which)
        .args(["-o", "src/generated"]);

    for (dir, files) in files {
        cmd.arg("-d");
        cmd.arg(dir);

        for file in *files {
            cmd.arg("-f");
            cmd.arg(format!("{dir}/{file}.proto"));
        }
    }

    if !cmd.status().expect("proto-gen was not installed").success() {
        panic!("proto-gen {which} failed");
    }
}

fn main() {
    let subcmd = std::env::args()
        .nth(1)
        .expect("expected a subcommand to execute");

    if !matches!(subcmd.as_str(), "generate" | "validate") {
        panic!("unexpected subcommmand '{subcmd}', expected 'generate' or 'validate'");
    }

    // Check if proto-gen is available and install it if not
    install();
    execute(&subcmd);
}
