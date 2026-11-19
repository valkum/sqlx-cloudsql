//! Connects to a Cloud SQL instance and prints the status of each connection attempt.
//!
//! ```sh
//! cargo run --example connect -- my-project:us-central1:my-instance \
//!     app@my-project.iam --database app --iam --lazy
//! ```
//!
//! Uses Application Default Credentials. Set `RUST_LOG=sqlx_cloudsql=debug` to see refreshes.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use sqlx::mysql::MySqlConnectOptions;
use sqlx::pool::{PoolConnectMetadata, PoolConnector, PoolOptions};
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Database, Pool};
use sqlx_cloudsql::{
    Connector, InstanceConnectionName, IpType, MySqlPoolConnector, PgPoolConnector, RefreshStrategy,
};

#[derive(Parser)]
struct Args {
    /// The instance connection name, `project:region:instance`.
    instance: InstanceConnectionName,

    /// The database user. With `--iam`, the IAM user name.
    user: String,

    /// The password of a built-in database user. Do not set it with `--iam`.
    #[arg(long, env = "DB_PASSWORD")]
    password: Option<String>,

    /// The database to connect to.
    #[arg(long)]
    database: Option<String>,

    /// Use IAM database authentication.
    #[arg(long)]
    iam: bool,

    /// Use the lazy refresh strategy instead of refresh-ahead.
    #[arg(long)]
    lazy: bool,

    /// The IP address type to connect to.
    #[arg(long, value_enum, default_value_t = Ip::Public)]
    ip: Ip,

    /// How many connections to open, one after the other.
    #[arg(long, default_value_t = 1)]
    rounds: u32,

    /// The seconds to wait between two rounds. Use a value above 3600 to test the
    /// refresh after the certificate expires.
    #[arg(long, default_value_t = 0)]
    interval: u64,

    /// The seconds that the pool tries to open one connection.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Ip {
    Public,
    Private,
    Psc,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("FAILED: {error}");
            let mut source = error.source();
            while let Some(error) = source {
                println!("  caused by: {error}");
                source = error.source();
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let started = Instant::now();
    let connector = Connector::builder()
        .iam_authn(args.iam)
        .refresh_strategy(if args.lazy {
            RefreshStrategy::Lazy
        } else {
            RefreshStrategy::RefreshAhead
        })
        .ip_type(match args.ip {
            Ip::Public => IpType::Public,
            Ip::Private => IpType::Private,
            Ip::Psc => IpType::Psc,
        })
        .build()
        .await?;
    println!("connector ready in {:?}", started.elapsed());

    let version = connector.engine_version(&args.instance).await?;
    println!("instance {} runs {version}", args.instance);

    let succeeded = match version.split('_').next() {
        Some("POSTGRES") => {
            let mut options = PgConnectOptions::new().username(&args.user);
            if let Some(password) = &args.password {
                options = options.password(password);
            }
            if let Some(database) = &args.database {
                options = options.database(database);
            }
            let adapter = PgPoolConnector::new(connector, args.instance.clone());
            rounds(args, &pool(args, adapter, options), "SELECT current_user").await
        }
        Some("MYSQL") => {
            let mut options = MySqlConnectOptions::new().username(&args.user);
            if let Some(password) = &args.password {
                options = options.password(password);
            }
            if let Some(database) = &args.database {
                options = options.database(database);
            }
            let adapter = MySqlPoolConnector::new(connector, args.instance.clone());
            rounds(args, &pool(args, adapter, options), "SELECT CURRENT_USER()").await
        }
        _ => return Err(format!("{version} is not supported").into()),
    };

    println!(
        "final status: {succeeded} of {} rounds succeeded",
        args.rounds
    );
    if succeeded == args.rounds {
        println!("OK");
        Ok(())
    } else {
        Err(format!("{} rounds failed", args.rounds - succeeded).into())
    }
}

/// Builds a pool with at most one connection, which opens connections with `connector`.
fn pool<DB: Database>(
    args: &Args,
    connector: impl PoolConnector<DB>,
    options: <DB::Connection as Connection>::Options,
) -> Pool<DB> {
    PoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(args.timeout))
        .connector(Logged(connector))
        .connect_lazy_with(options)
}

/// Wraps a connector and prints the result of each connection attempt of the pool.
struct Logged<C>(C);

impl<DB: Database, C: PoolConnector<DB>> PoolConnector<DB> for Logged<C> {
    async fn connect(&self, meta: PoolConnectMetadata<DB>) -> sqlx::Result<DB::Connection> {
        let attempt = meta.num_attempts;
        let started = Instant::now();
        let result = self.0.connect(meta).await;
        match &result {
            Ok(_) => println!("  attempt {attempt}: connected in {:?}", started.elapsed()),
            Err(error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolConnector {
                        retryable: true,
                        ..
                    }
                );
                println!(
                    "  attempt {attempt}: failed after {:?} (retryable: {retryable}): {error}",
                    started.elapsed()
                );
            }
        }
        result
    }
}

/// Opens a new connection in each round and runs `query`, which returns the user.
/// Returns the number of rounds that succeeded.
async fn rounds<DB>(args: &Args, pool: &Pool<DB>, query: &'static str) -> u32
where
    DB: Database,
    for<'c> &'c mut DB::Connection: sqlx::Executor<'c, Database = DB>,
    for<'q> DB::Arguments: sqlx::IntoArguments<DB>,
    String: sqlx::Type<DB> + for<'r> sqlx::Decode<'r, DB>,
    usize: sqlx::ColumnIndex<DB::Row>,
{
    let mut succeeded = 0;

    for round in 1..=args.rounds {
        if round > 1 && args.interval > 0 {
            println!("waiting {} s", args.interval);
            tokio::time::sleep(Duration::from_secs(args.interval)).await;
        }

        println!("round {round}:");
        let started = Instant::now();
        let result = async {
            let mut conn = pool.acquire().await?;
            let user: String = sqlx::query_scalar(query).fetch_one(&mut *conn).await?;
            // Close the connection, so that the next round opens a new one.
            conn.close().await?;
            Ok::<_, sqlx::Error>(user)
        }
        .await;

        match result {
            Ok(user) => {
                succeeded += 1;
                println!("  OK in {:?}: connected as {user}", started.elapsed());
            }
            Err(error) => println!("  FAILED after {:?}: {error}", started.elapsed()),
        }
    }

    succeeded
}
