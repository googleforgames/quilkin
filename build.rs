/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::io::{Error, ErrorKind, Result as IoResult};

/// Reads the contents of a git file, and registers the build to rerun if it changes
fn read_git_file(file_path: String) -> IoResult<String> {
    let string = std::fs::read_to_string(&file_path)?;
    println!("cargo:rerun-if-changed={file_path}");
    Ok(string)
}

fn git_path(path: &str) -> IoResult<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-path", path])
        .output()
        .map_err(|e| Error::new(e.kind(), "failed to run `git`"))?;

    if !output.status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "`git` failed with status {}: {}",
                output.status,
                std::str::from_utf8(&output.stderr).unwrap_or("no output")
            ),
        ));
    }

    // Trim whitespace cruft
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_e| Error::new(ErrorKind::InvalidData, "`git` output was not utf-8"))?
        .trim();

    if output.is_empty() {
        Err(Error::new(ErrorKind::InvalidData, "`git` output was empty"))
    } else {
        Ok(output.to_owned())
    }
}

/// Embed the git commit hash into the binary
fn embed_commit_hash() -> Result<(), (Error, &'static str)> {
    // 1. Read HEAD (this should always be .git/HEAD, but better safe than sorry)
    let head_path = git_path("HEAD").map_err(|e| (e, "failed to get HEAD path"))?;
    let head_contents = read_git_file(head_path).map_err(|e| (e, "failed to read HEAD"))?;

    // 2. HEAD usually points to symbolic ref, so peel that to the actual SHA1
    let commit = if let Some(ref_path) = head_contents.strip_prefix("ref: ") {
        let ref_path = git_path(ref_path).map_err(|e| (e, "failed to get ref path"))?;
        read_git_file(ref_path).map_err(|e| (e, "failed to read ref"))?
    } else {
        head_contents
    };

    // 3. Profit
    println!("cargo:rustc-env=GIT_COMMIT_HASH={commit}");

    Ok(())
}

// This build script is used to generate the rust source files that
// we need for XDS GRPC communication.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let proto_files = vec![
    //     "proto/data-plane-api/envoy/config/accesslog/v3/accesslog.proto",
    //     "proto/data-plane-api/envoy/config/cluster/v3/cluster.proto",
    //     "proto/data-plane-api/envoy/config/common/matcher/v3/matcher.proto",
    //     "proto/data-plane-api/envoy/config/listener/v3/listener.proto",
    //     "proto/data-plane-api/envoy/config/listener/v3/listener_components.proto",
    //     "proto/data-plane-api/envoy/config/route/v3/route.proto",
    //     "proto/data-plane-api/envoy/service/cluster/v3/cds.proto",
    //     "proto/data-plane-api/envoy/service/discovery/v3/ads.proto",
    //     "proto/data-plane-api/envoy/service/discovery/v3/discovery.proto",
    //     "proto/data-plane-api/envoy/type/metadata/v3/metadata.proto",
    //     "proto/data-plane-api/envoy/type/tracing/v3/custom_tag.proto",
    //     "proto/quilkin/relay/v1alpha1/relay.proto",
    //     "proto/quilkin/config/v1alpha1/config.proto",
    //     "proto/quilkin/filters/capture/v1alpha1/capture.proto",
    //     "proto/quilkin/filters/compress/v1alpha1/compress.proto",
    //     "proto/quilkin/filters/concatenate/v1alpha1/concatenate.proto",
    //     "proto/quilkin/filters/debug/v1alpha1/debug.proto",
    //     "proto/quilkin/filters/drop/v1alpha1/drop.proto",
    //     "proto/quilkin/filters/firewall/v1alpha1/firewall.proto",
    //     "proto/quilkin/filters/load_balancer/v1alpha1/load_balancer.proto",
    //     "proto/quilkin/filters/local_rate_limit/v1alpha1/local_rate_limit.proto",
    //     "proto/quilkin/filters/match/v1alpha1/match.proto",
    //     "proto/quilkin/filters/pass/v1alpha1/pass.proto",
    //     "proto/quilkin/filters/token_router/v1alpha1/token_router.proto",
    //     "proto/quilkin/filters/timestamp/v1alpha1/timestamp.proto",
    //     "proto/udpa/xds/core/v3/resource_name.proto",
    // ]
    // .iter()
    // .map(|name| std::env::current_dir().unwrap().join(name))
    // .collect::<Vec<_>>();

    // let include_dirs = [
    //     "proto/data-plane-api",
    //     "proto/udpa",
    //     "proto/googleapis",
    //     "proto/protoc-gen-validate",
    //     "proto/quilkin",
    // ]
    // .iter()
    // .map(|i| std::env::current_dir().unwrap().join(i))
    // .collect::<Vec<_>>();

    // let config = {
    //     let mut c = prost_build::Config::new();
    //     c.disable_comments(Some("."));
    //     c
    // };
    // tonic_build::configure()
    //     .build_server(true)
    //     .compile_with_config(
    //         config,
    //         &proto_files
    //             .iter()
    //             .map(|path| path.to_str().unwrap())
    //             .collect::<Vec<_>>(),
    //         &include_dirs
    //             .iter()
    //             .map(|p| p.to_str().unwrap())
    //             .collect::<Vec<_>>(),
    //     )?;

    // // This tells cargo to re-run this build script only when the proto files
    // // we're interested in change or the any of the proto directories were updated.
    // for path in [proto_files, include_dirs].concat() {
    //     println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
    // }

    // We could use an env var etc to make this fatal if needed
    if let Err((err, details)) = embed_commit_hash() {
        println!("cargo:warning={details}: {err}");
    }

    Ok(())
}
