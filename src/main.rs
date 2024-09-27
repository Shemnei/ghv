// TODO:
// - Unify repo fetching (e.g. iter over all repos which can be used by download and verify)
// - Decide on rego output (probably deny based with msgs)
// - Decide on subset of modules to support
// - (Rego testing support)

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::{eyre::Ok, Result};
use octocrab::Octocrab;
use regorus::{Engine, Value};
use secrecy::SecretString;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use walkdir::WalkDir;

#[derive(Args)]
struct Rego {
    #[clap(long)]
    package: Option<String>,

    #[clap(long)]
    output: Option<String>,
}

impl Rego {
    pub fn rule_path(&self, model: Model) -> String {
        format!(
            "data.{}.{}",
            self.package.as_deref().unwrap_or(model.package_name()),
            self.output.as_deref().unwrap_or(model.output_name())
        )
    }
}

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
    Download(Download),
}

#[derive(Args)]
struct Verify {
    #[clap(flatten)]
    rego: Rego,

    #[clap(short, long, value_enum)]
    model: Model,

    #[clap(short, long, value_parser, num_args = 0.., value_delimiter = ',')]
    input: Vec<PathBuf>,

    policy: PathBuf,
}

#[derive(Args)]
struct Download {
    #[clap(short, long, value_enum)]
    model: Model,

    output: PathBuf,
}

trait ModelX {
    type Output;

    fn package_name(&self) -> &'static str;
    fn output_name(&self) -> &'static str;
    fn eval_output(&self, output: regorus::Value) -> Result<Self::Output>;
}

#[derive(Debug, Clone, ValueEnum)]
enum Model {
    Repos,
}

impl Model {
    pub fn id(&self) -> &'static str {
        match self {
            Model::Repos => "repos",
        }
    }

    pub fn package_name(&self) -> &'static str {
        self.id()
    }

    pub fn output_name(&self) -> &'static str {
        "deny"
    }
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
        Command::Download(download) => handle_download(gh, download).await,
    }
}

async fn handle_download(gh: Octocrab, download: Download) -> Result<()> {
    let all_repos = gh
        .all_pages(
            gh.current()
                .list_repos_for_authenticated_user()
                .visibility("all")
                .affiliation("owner,collaborator,organization_member")
                // NOT ALLOWED WITH `visibility` or `affiliation` .type_("all")
                .sort("updated")
                .direction("desc")
                .send()
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    for repo in all_repos {
        println!(
            "Scanning repo `{}`",
            repo.full_name.as_ref().unwrap_or(&repo.name)
        );

        let path = download
            .output
            .join(download.model.id())
            .join(format!("{}.json", repo.id));

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let out = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)
            .unwrap();

        serde_json::to_writer_pretty(out, &repo).unwrap();
    }

    Ok(())
}

async fn handle_verify(gh: Octocrab, verify: Verify) -> Result<()> {
    let engine = {
        let mut engine = regorus::Engine::new();
        engine.add_policy_from_file(verify.policy).unwrap();
        engine.set_rego_v1(true);
        engine.set_strict_builtin_errors(true);

        engine
    };

    match verify.model {
        Model::Repos => handle_verify_repos(gh, engine, verify.rego, verify.input).await,
    }
}

async fn handle_verify_repos(
    gh: Octocrab,
    mut engine: Engine,
    rego: Rego,
    input: Vec<PathBuf>,
) -> Result<()> {
    let mut dedup_repos: HashMap<octocrab::models::RepositoryId, regorus::Value> = HashMap::new();

    if input.is_empty() {
        // Self
        let all_repos = gh
            .all_pages(
                gh.current()
                    .list_repos_for_authenticated_user()
                    .visibility("all")
                    .affiliation("owner,collaborator,organization_member")
                    .type_("all")
                    .sort("updated")
                    .direction("desc")
                    .send()
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();

        for repo in all_repos {
            println!(
                "Scanning repo `{}`",
                repo.full_name.as_ref().unwrap_or(&repo.name)
            );

            let json = serde_json::to_string(&repo).unwrap();
            dedup_repos.insert(repo.id, Value::from_json_str(&json).unwrap());
        }
    } else {
        for input in input {
            for file in WalkDir::new(input)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|f| f.metadata().unwrap().is_file())
            {
                let repo: octocrab::models::Repository =
                    serde_json::from_reader(File::open(file.path()).unwrap()).unwrap();

                println!(
                    "Scanning repo `{}` (id: `{}`)",
                    repo.full_name.as_ref().unwrap_or(&repo.name),
                    repo.id
                );

                let json = serde_json::to_string(&repo).unwrap();
                dedup_repos.insert(repo.id, Value::from_json_str(&json).unwrap());
            }
        }
    }

    let rule_path = rego.rule_path(Model::Repos);

    for (id, repo) in dedup_repos {
        println!("Evaluating repo `{id}` for `{rule_path}`");

        engine.set_input(repo);

        let r = engine.eval_rule(rule_path.clone()).unwrap();

        println!(">> {r:#?}");
    }

    Ok(())
}
