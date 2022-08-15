/*
 * Copyright 2022 Google LLC
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

mod generate_config_schema;
mod manage;
mod run;

use std::path::PathBuf;

use crate::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(clap::Parser)]
pub struct Cli {
    #[clap(
        short,
        long,
        env = "QUILKIN_CONFIG",
        default_value = "quilkin.yaml",
        help = "The YAML configuration file."
    )]
    config: PathBuf,
    #[clap(
        short,
        long,
        env,
        help = "Whether Quilkin will report any results to stdout/stderr."
    )]
    quiet: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Run(run::Run),
    GenerateConfigSchema(generate_config_schema::GenerateConfigSchema),
    Manage(manage::Manage),
}

impl Cli {
    /// Drives the main quilkin application lifecycle using the command line
    /// arguments.
    pub async fn drive(self) -> crate::Result<()> {
        let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
            format!("{VERSION}+debug").into()
        } else {
            VERSION.into()
        };

        if !self.quiet {
            let env_filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy();
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        }

        tracing::info!(
            version = &*version,
            commit = crate::metadata::build::GIT_COMMIT_HASH,
            "Starting Quilkin"
        );

        match &self.command {
            Commands::Run(runner) => runner.run(&self).await,
            Commands::Manage(manager) => manager.manage(&self).await,
            Commands::GenerateConfigSchema(generator) => generator.generate_config_schema(),
        }
    }

    /// Searches for the configuration file, and panics if not found.
    fn read_config(&self) -> Config {
        std::fs::File::open(&self.config)
            .or_else(|error| {
                if cfg!(unix) {
                    std::fs::File::open("/etc/quilkin/quilkin.yaml")
                } else {
                    Err(error)
                }
            })
            .map_err(eyre::Error::from)
            .and_then(|file| Config::from_reader(file).map_err(From::from))
            .unwrap()
    }
}
