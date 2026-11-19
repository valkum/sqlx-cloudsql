use sqlx::mysql::{MySql, MySqlConnection, MySqlSslMode};
use sqlx::pool::{PoolConnectMetadata, PoolConnector};

use crate::{Connector, InstanceConnectionName};

/// Opens sqlx MySQL connections to a Cloud SQL instance. Set it with `PoolOptions::connector`.
/// The host, port and SSL mode in the connect options are not used.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use sqlx_cloudsql::{Connector, MySqlPoolConnector};
/// use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
///
/// let connector = Connector::builder().iam_authn(true).build().await?;
/// let instance = "my-project:us-central1:my-instance".parse()?;
///
/// let pool = MySqlPoolOptions::new()
///     .connector(MySqlPoolConnector::new(connector, instance))
///     .connect_with(MySqlConnectOptions::new().username("app").database("app"))
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MySqlPoolConnector {
    connector: Connector,
    instance: InstanceConnectionName,
}

impl MySqlPoolConnector {
    pub fn new(connector: Connector, instance: InstanceConnectionName) -> Self {
        Self {
            connector,
            instance,
        }
    }
}

impl PoolConnector<MySql> for MySqlPoolConnector {
    async fn connect(&self, meta: PoolConnectMetadata<MySql>) -> sqlx::Result<MySqlConnection> {
        let stream = self
            .connector
            .connect_engine(&self.instance, "MYSQL")
            .await?;

        // The stream is already a TLS connection. MySQL must not upgrade it to TLS.
        let options = (*meta.connect_options)
            .clone()
            .ssl_mode(MySqlSslMode::Disabled);
        MySqlConnection::connect_raw_tokio(stream, &options).await
    }
}
