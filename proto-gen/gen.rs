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
        let mut child = Command::new("tar")
            .args(["xzf", "-", "--strip-components=1", "-C"])
            .arg(cargo_root)
            .arg(format!(
                "proto-gen-v{VERSION}-x86_64-unknown-linux-musl/proto-gen"
            ))
            .stdin(Stdio::piped())
            .spawn()
            .expect("tar not installed");

        {
            let mut stdin = child.stdin.take().unwrap();
            use std::io::Write;
            stdin
                .write_all(&output.stdout)
                .expect("failed to write tarball to stdin");
        }

        if !child.wait().expect("tar is not installed").success() {
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
            "proto",
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
        ("proto/xds", &["core/v3/resource_name"]),
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
        .arg("--format")
        .arg("--build-server")
        .arg("--build-client")
        .arg("--generate-transport")
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

fn copy() {
    struct Source {
        name: &'static str,
        repo: &'static str,
        rev: &'static str,
        root: &'static str,
        target: &'static str,
    }

    impl Source {
        fn sync(&self) -> PathBuf {
            let path = self.path();

            if path.exists() {
                return path;
            }

            if !Command::new("git")
                .arg("clone")
                .arg(self.repo)
                .arg(&path)
                .status()
                .expect("git not installed")
                .success()
            {
                panic!("failed to clone {} from {}", self.name, self.repo);
            }

            if !Command::new("git")
                .arg("-C")
                .arg(&path)
                .arg("checkout")
                .arg(self.rev)
                .status()
                .unwrap()
                .success()
            {
                panic!("failed to checkout {} from {}", self.rev, self.repo);
            }

            path
        }

        fn path(&self) -> PathBuf {
            format!("/tmp/{}-{}", self.name, &self.rev[..7]).into()
        }
    }

    const REPOS: &[Source] = &[
        Source {
            name: "envoy",
            repo: "https://github.com/envoyproxy/data-plane-api",
            rev: "a04278879ba6eb9264d755936942b23cbf552a04",
            root: "envoy",
            target: "envoy",
        },
        Source {
            name: "xds",
            repo: "https://github.com/cncf/xds",
            rev: "4a2b9fdd466b16721f8c058d7cadf5a54e229d66",
            root: "xds",
            target: "xds",
        },
    ];

    let args: Vec<_> = std::env::args().skip(2).collect();
    let name = args.get(0).expect("must provide source name");
    let path = args.get(1).expect("must provide path");

    let Some(ri) = REPOS.iter().find(|r| r.name == name) else {
        panic!("unknown repo '{name}'")
    };

    let mut pb = ri.sync();
    pb.push(ri.root);
    pb.push(path);

    if !pb.exists() {
        panic!("failed to find {pb:?}");
    }

    let tp = path.replace("type", "kind");

    let mut tbp = PathBuf::new();
    tbp.push("proto");
    tbp.push(ri.target);
    tbp.push(tp);

    {
        let parent = tbp.parent().unwrap();
        if !parent.exists() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                panic!("failed to create directory {parent:?}: {err}");
            }
        }
    }

    if let Err(err) = std::fs::copy(&pb, &tbp) {
        panic!("failed to copy {pb:?} -> {tbp:?}: {err}");
    } else {
        println!("copied {pb:?} -> {tbp:?}");
    }
}

fn main() {
    let subcmd = std::env::args()
        .nth(1)
        .expect("expected a subcommand to execute");

    if !matches!(subcmd.as_str(), "generate" | "validate" | "copy") {
        panic!("unexpected subcommmand '{subcmd}', expected 'generate', 'validate', or 'copy'");
    }

    if subcmd == "copy" {
        copy();
        return;
    }

    // Check if proto-gen is available and install it if not
    install();
    execute(&subcmd);
}
