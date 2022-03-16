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

use std::path::PathBuf;

use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(clap::Parser)]
struct Cli {
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
    Run,
    GenerateConfigSchema {
        #[clap(
            short,
            long,
            default_value = ".",
            help = "The directory to write configuration files."
        )]
        output_directory: PathBuf,
        #[clap(
            min_values = 1,
            default_value = "all",
            help = "A list of one or more filter IDs to generate or 'all' to generate all available filter schemas."
        )]
        filter_ids: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> quilkin::Result<()> {
    stable_eyre::install()?;
    let version: std::borrow::Cow<'static, str> = if cfg!(debug_assertions) {
        format!("{VERSION}+debug").into()
    } else {
        VERSION.into()
    };

    let cli = <Cli as clap::Parser>::parse();

    if !cli.quiet {
        tracing_subscriber::fmt().json().with_target(false).init();
    }

    info!(version = &*version, "Starting Quilkin");
    match cli.command {
        Commands::Run => {
            let config = std::fs::File::open(cli.config)
                .or_else(|error| {
                    if cfg!(unix) {
                        std::fs::File::open("/etc/quilkin/quilkin.yaml")
                    } else {
                        Err(error)
                    }
                })
                .map_err(eyre::Error::from)
                .and_then(|file| quilkin::Config::from_reader(file).map_err(From::from))?;

            quilkin::run(config, vec![]).await
        }

        Commands::GenerateConfigSchema {
            output_directory,
            filter_ids,
        } => {
            let set = quilkin::filters::FilterSet::default();
            type SchemaIterator<'r> =
                Box<dyn Iterator<Item = (&'static str, schemars::schema::RootSchema)> + 'r>;

            let schemas = (filter_ids.len() == 1 && filter_ids[0].to_lowercase() == "all")
                .then(|| {
                    Box::new(
                        set.iter()
                            .map(|factory| (factory.name(), factory.config_schema())),
                    ) as SchemaIterator
                })
                .unwrap_or_else(|| {
                    Box::new(filter_ids.iter().filter_map(|id| {
                        let item = set.get(id);

                        if item.is_none() {
                            tracing::error!("{id} not found in filter set.");
                        }

                        item.map(|item| (item.name(), item.config_schema()))
                    })) as SchemaIterator
                });

            for (id, schema) in schemas {
                let mut path = output_directory.join(id);
                path.set_extension("yaml");

                tracing::info!("Writing {id} schema to {}", path.display());

                std::fs::write(path, serde_yaml::to_string(&schema)?)?;
            }

            Ok(())
        }
    }
}
