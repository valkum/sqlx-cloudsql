//! sqlx pools through the fake server-side proxy to a real database.
//!
//! Set `CLOUDSQL_TEST_POSTGRES_URL` or `CLOUDSQL_TEST_MYSQL_URL` to run the database tests,
//! for example with the containers of `tests/docker-compose.yml` in the sqlx repository.

mod mock;

use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use google_cloud_auth::credentials::anonymous;
use sqlx::Executor;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx_cloudsql::{Connector, MySqlPoolConnector, PgPoolConnector, RefreshStrategy};

use mock::{Backend, FakeAdminApi, FakeInstance, FakeServerProxy};

async fn connector(admin: &FakeAdminApi) -> Connector {
    mock::install_provider();
    Connector::builder()
        .credentials(anonymous::Builder::new().build())
        .admin_api_endpoint(&admin.url)
        .refresh_strategy(RefreshStrategy::Lazy)
        .build()
        .await
        .unwrap()
}

fn instance(database_version: &str) -> FakeInstance {
    let mut instance = FakeInstance::new("my-project", "my-region", "my-instance");
    instance.database_version = database_version.into();
    instance
}

fn addr(host: &str, port: u16) -> SocketAddr {
    (host, port).to_socket_addrs().unwrap().next().unwrap()
}

#[tokio::test]
async fn postgres_through_proxy() {
    let Ok(url) = std::env::var("CLOUDSQL_TEST_POSTGRES_URL") else {
        eprintln!("CLOUDSQL_TEST_POSTGRES_URL is not set, skipping");
        return;
    };
    let options = PgConnectOptions::from_str(&url).unwrap();
    let backend = Backend::Forward(addr(options.get_host(), options.get_port()));

    let (admin, instance) = FakeAdminApi::start(instance("POSTGRES_17")).await;
    let _proxy = FakeServerProxy::start(&instance, backend).await;
    let adapter = PgPoolConnector::new(connector(&admin).await, instance.connection_name());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connector(adapter)
        .connect_with(options)
        .await
        .unwrap();
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);
}

#[tokio::test]
async fn mysql_through_proxy() {
    let Ok(url) = std::env::var("CLOUDSQL_TEST_MYSQL_URL") else {
        eprintln!("CLOUDSQL_TEST_MYSQL_URL is not set, skipping");
        return;
    };
    let options = MySqlConnectOptions::from_str(&url).unwrap();
    let backend = Backend::Forward(addr(options.get_host(), options.get_port()));

    let (admin, instance) = FakeAdminApi::start(instance("MYSQL_8_0")).await;
    let _proxy = FakeServerProxy::start(&instance, backend).await;
    let adapter = MySqlPoolConnector::new(connector(&admin).await, instance.connection_name());

    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connector(adapter)
        .connect_with(options)
        .await
        .unwrap();
    let one: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);
}

/// `caching_sha2_password` full authentication over the proxy. sqlx does not see TLS, so it
/// encrypts the password with the RSA key of the server.
#[tokio::test]
async fn mysql_caching_sha2_full_auth_through_proxy() {
    let Ok(url) = std::env::var("CLOUDSQL_TEST_MYSQL_URL") else {
        eprintln!("CLOUDSQL_TEST_MYSQL_URL is not set, skipping");
        return;
    };
    let admin_options = MySqlConnectOptions::from_str(&url).unwrap();
    let backend = Backend::Forward(addr(admin_options.get_host(), admin_options.get_port()));

    // A new user has no cached password on the server, so the first login is a full
    // authentication.
    let setup = MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(admin_options.clone())
        .await
        .unwrap();
    setup
        .execute("DROP USER IF EXISTS 'cloudsql_rsa'@'%'")
        .await
        .unwrap();
    setup
        .execute("CREATE USER 'cloudsql_rsa'@'%' IDENTIFIED WITH caching_sha2_password BY 'secret'")
        .await
        .unwrap();
    setup
        .execute("GRANT SELECT ON *.* TO 'cloudsql_rsa'@'%'")
        .await
        .unwrap();
    setup.execute("FLUSH PRIVILEGES").await.unwrap();

    let (admin, instance) = FakeAdminApi::start(instance("MYSQL_8_0")).await;
    let _proxy = FakeServerProxy::start(&instance, backend).await;
    let adapter = MySqlPoolConnector::new(connector(&admin).await, instance.connection_name());

    let options = admin_options.username("cloudsql_rsa").password("secret");
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connector(adapter)
        .connect_with(options)
        .await
        .unwrap();
    let user: String = sqlx::query_scalar("SELECT CURRENT_USER()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(user, "cloudsql_rsa@%");
}

/// A Postgres pool connector refuses a MySQL instance before it connects.
#[tokio::test]
async fn postgres_pool_rejects_mysql_instance() {
    let (admin, instance) = FakeAdminApi::start(instance("MYSQL_8_0")).await;
    let adapter = PgPoolConnector::new(connector(&admin).await, instance.connection_name());

    let error = PgPoolOptions::new()
        .connector(adapter)
        .connect_with(PgConnectOptions::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            sqlx::Error::PoolConnector {
                retryable: false,
                ..
            }
        ),
        "{error}"
    );
}
