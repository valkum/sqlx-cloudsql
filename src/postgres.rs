use sqlx::pool::{PoolConnectMetadata, PoolConnector};
use sqlx::postgres::{PgConnection, PgSslMode, Postgres};

use crate::{Connector, InstanceConnectionName};

/// Opens sqlx Postgres connections to a Cloud SQL instance. Set it with `PoolOptions::connector`.
/// The host, port and SSL mode in the connect options are not used.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use sqlx_cloudsql::{Connector, PgPoolConnector};
/// use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
///
/// let connector = Connector::builder().iam_authn(true).build().await?;
/// let instance = "my-project:us-central1:my-instance".parse()?;
///
/// let pool = PgPoolOptions::new()
///     .connector(PgPoolConnector::new(connector, instance))
///     .connect_with(
///         PgConnectOptions::new()
///             .username("app@my-project.iam")
///             .database("app"),
///     )
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct PgPoolConnector {
    connector: Connector,
    instance: InstanceConnectionName,
}

impl PgPoolConnector {
    pub fn new(connector: Connector, instance: InstanceConnectionName) -> Self {
        Self {
            connector,
            instance,
        }
    }
}

impl PoolConnector<Postgres> for PgPoolConnector {
    async fn connect(&self, meta: PoolConnectMetadata<Postgres>) -> sqlx::Result<PgConnection> {
        let stream = self
            .connector
            .connect_engine(&self.instance, "POSTGRES")
            .await?;

        // The stream is already a TLS connection. Postgres must not send an
        // SSLRequest in it.
        let options = (*meta.connect_options).clone().ssl_mode(PgSslMode::Disable);
        PgConnection::connect_raw_tokio(stream, &options).await
    }
}
