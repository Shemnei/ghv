use std::{collections::HashMap, path::PathBuf};

use chrono::{DateTime, Datelike, Utc};
use clap::{Args, Parser, Subcommand};
use color_eyre::Result;
use octocrab::{params, Octocrab};
use regorus::{Engine, Value};
use secrecy::SecretString;
use serde_json::json;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
struct Opts {
    #[clap(long, env = "GITHUB_TOKEN")]
    token: SecretString,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify(Verify),
}

#[derive(Args)]
struct Verify {
    #[command(subcommand)]
    model: Model,
    policy: PathBuf,
}

#[derive(Subcommand)]
enum Model {
    Repos,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    if let Err(err) = dotenvy::dotenv() {
        info!(error = ?err, "Failed to load env file");
    }

    let opts = Opts::parse();

    let gh = Octocrab::builder().personal_token(opts.token).build()?;

    match opts.command {
        Command::Verify(verify) => handle_verify(gh, verify).await,
    }
}

async fn handle_verify(gh: Octocrab, verify: Verify) -> Result<()> {
    let engine = {
        let mut engine = regorus::Engine::new();
        let policy = std::fs::read_to_string(&verify.policy)?;
        engine
            .add_policy(verify.policy.to_string_lossy().to_string(), policy)
            .unwrap();

        engine
    };

    match verify.model {
        Model::Repos => handle_verify_repos(gh, engine).await,
    }
}

// async fn handle_verify_repos(gh: Octocrab, mut engine: Engine) -> Result<()> {
//     let mock_repo: serde_json::Value = json!({
//         "updated_at": Utc::now().with_year(2023).unwrap(),
//     });
//
//     let json = serde_json::to_string_pretty(&mock_repo).unwrap();
//     println!("{json}");
//
//     engine.set_input(Value::from_json_str(&json).unwrap());
//
//     let r = engine.eval_rule("data.example.deny".to_string()).unwrap();
//
//     println!(">> {r:#?}");
//
//     Ok(())
// }
//
async fn handle_verify_repos(gh: Octocrab, mut engine: Engine) -> Result<()> {
    let orgs = gh
        .current()
        .list_org_memberships_for_authenticated_user()
        .send()
        .await?;

    let mut repos = HashMap::new();

    for org in orgs {
        let name = org.organization.login;

        println!("Scanning org `{name}`");

        let org_repos = gh
            .orgs(name)
            .list_repos()
            .repo_type(params::repos::Type::Sources)
            .sort(params::repos::Sort::Pushed)
            .direction(params::Direction::Descending)
            .send()
            .await?;

        for repo in org_repos {
            println!(
                "Scanning repo `{}`",
                repo.full_name.as_ref().unwrap_or(&repo.name)
            );

            repos.insert(repo.id, repo);
        }
    }

    for repo in repos.into_values() {
        println!(
            "Evaluating repo `{}`",
            repo.full_name.as_ref().unwrap_or(&repo.name)
        );

        let input = serde_json::to_string(&repo)?;

        engine.set_input(Value::from_json_str(&input).unwrap());

        let r = engine.eval_rule("data.example.deny".to_string()).unwrap();

        println!(">> {r:#?}");
    }
}
