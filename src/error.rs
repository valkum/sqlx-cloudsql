use std::io;
use std::sync::Arc;

use crate::InstanceConnectionName;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type SharedError = Arc<dyn std::error::Error + Send + Sync + 'static>;

/// An error from the connector. Cheap to clone, so one failed refresh reaches all waiters.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The configuration is not valid, for example a bad connection name. Not retryable.
    #[error("invalid Cloud SQL configuration: {0}")]
    Config(String),

    /// Getting credentials or an access token failed.
    #[error("failed to get Google Cloud credentials: {0}")]
    Auth(#[source] SharedError),

    /// A call to the Cloud SQL Admin API failed.
    #[error("Cloud SQL Admin API call failed: {source}")]
    Api {
        #[source]
        source: SharedError,
        /// `true` if the call can succeed when it is tried again, for example after an
        /// HTTP 5xx status.
        retryable: bool,
    },

    /// Generating or encoding the RSA client key failed. Not retryable.
    #[error("failed to create the RSA client key: {0}")]
    Key(#[source] SharedError),

    /// A certificate or TLS setting from the Admin API is not valid.
    #[error("invalid certificate data for {instance}: {source}")]
    Certificate {
        instance: String,
        #[source]
        source: SharedError,
    },

    /// The TLS handshake with the instance failed.
    #[error("TLS handshake with {instance} failed: {source}")]
    Handshake {
        instance: String,
        #[source]
        source: Arc<io::Error>,
    },

    /// The TCP connection to the instance failed.
    #[error("failed to connect to Cloud SQL instance: {0}")]
    Io(#[source] Arc<io::Error>),
}

impl Error {
    /// Returns `true` if the operation can succeed when it is tried again.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Config(_) | Error::Key(_) => false,
            Error::Api { retryable, .. } => *retryable,
            Error::Auth(_) | Error::Certificate { .. } | Error::Handshake { .. } | Error::Io(_) => {
                true
            }
        }
    }

    pub(crate) fn auth(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Error::Auth(Arc::new(error))
    }

    pub(crate) fn key(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Error::Key(Arc::new(error))
    }

    pub(crate) fn certificate(
        instance: &InstanceConnectionName,
        error: impl Into<BoxError>,
    ) -> Self {
        Error::Certificate {
            instance: instance.to_string(),
            source: Arc::from(error.into()),
        }
    }

    pub(crate) fn api(
        error: impl std::error::Error + Send + Sync + 'static,
        retryable: bool,
    ) -> Self {
        Error::Api {
            source: Arc::new(error),
            retryable,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(Arc::new(error))
    }
}

impl From<Error> for sqlx::Error {
    fn from(error: Error) -> Self {
        sqlx::Error::PoolConnector {
            retryable: error.is_retryable(),
            source: Box::new(error),
        }
    }
}
