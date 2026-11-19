//! Connect sqlx pools to Google Cloud SQL instances. A port of the
//! [Go connector](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector).

mod admin;
mod connector;
mod error;
#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "postgres")]
mod postgres;
mod refresh;

pub use connector::{
    CloudSqlStream, Connector, ConnectorBuilder, InstanceConnectionName, IpType, RefreshStrategy,
};
pub use error::Error;
#[cfg(feature = "mysql")]
pub use mysql::MySqlPoolConnector;
#[cfg(feature = "postgres")]
pub use postgres::PgPoolConnector;
