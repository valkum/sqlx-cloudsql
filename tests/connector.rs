//! Tests against a fake Admin API and a fake server-side proxy, same as `dialer_test.go` in
//! the Go connector.

mod mock;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use google_cloud_auth::credentials::{
    AccessToken, AccessTokenCredentials, AccessTokenCredentialsProvider, CacheableResource,
    CredentialsProvider, EntityTag, anonymous,
};
use google_cloud_auth::errors::CredentialsError;
use http::{Extensions, HeaderMap};
use sqlx_cloudsql::{CloudSqlStream, Connector, ConnectorBuilder, Error, IpType, RefreshStrategy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use mock::{Backend, Ca, FakeAdminApi, FakeInstance, FakeServerProxy, ServerName};

async fn connector(
    admin: &FakeAdminApi,
    f: impl FnOnce(ConnectorBuilder) -> ConnectorBuilder,
) -> Connector {
    mock::install_provider();
    let builder = Connector::builder()
        .credentials(anonymous::Builder::new().build())
        .admin_api_endpoint(&admin.url)
        .refresh_strategy(RefreshStrategy::Lazy);
    f(builder).build().await.unwrap()
}

/// Sends data through the echo proxy and checks that it comes back.
async fn ping(stream: &mut CloudSqlStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

fn instance() -> FakeInstance {
    FakeInstance::new("my-project", "my-region", "my-instance")
}

#[tokio::test]
async fn connects_with_legacy_common_name() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    let mut stream = connector
        .connect(&instance.connection_name())
        .await
        .unwrap();
    ping(&mut stream).await;
}

#[tokio::test]
async fn connects_with_dns_name_with_trailing_dot() {
    let instance = instance().with_dns_name("abc.my-region.sql.goog");
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    let mut stream = connector
        .connect(&instance.connection_name())
        .await
        .unwrap();
    ping(&mut stream).await;
}

#[tokio::test]
async fn rejects_server_cert_of_other_instance() {
    let mut instance = instance();
    instance.server_name = ServerName::LegacyCn("my-project:other-instance".into());
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .connect(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Handshake { .. }), "{error}");
    assert!(error.is_retryable());
}

#[tokio::test]
async fn rejects_server_cert_of_other_dns_name() {
    let mut instance = instance().with_dns_name("abc.my-region.sql.goog");
    instance.server_name = ServerName::DnsSan("other.my-region.sql.goog.".into());
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .connect(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Handshake { .. }), "{error}");
}

#[tokio::test]
async fn rejects_untrusted_server_ca() {
    let mut instance = instance();
    instance.server_signer = Arc::new(Ca::new("Other CA"));
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .connect(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Handshake { .. }), "{error}");
}

#[tokio::test]
async fn rejects_region_mismatch() {
    let mut instance = instance();
    instance.region = "other-region".into();
    let name = "my-project:my-region:my-instance".parse().unwrap();
    let (admin, _instance) = FakeAdminApi::start(instance).await;
    let connector = connector(&admin, |b| b).await;

    let error = connector.engine_version(&name).await.unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error}");
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn rejects_first_generation_instance() {
    let mut instance = instance();
    instance.backend_type = "FIRST_GEN".into();
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error}");
}

#[tokio::test]
async fn rejects_missing_ip_type() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let connector = connector(&admin, |b| b.ip_type(IpType::Private)).await;

    let error = connector
        .connect(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error}");
}

#[tokio::test]
async fn retries_admin_api_5xx() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    admin.fail_connect_settings(&[500, 503]);
    let connector = connector(&admin, |b| b).await;

    let version = connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap();
    assert_eq!(version, "POSTGRES_17");
    assert_eq!(admin.calls(|c| c.connect_settings), 3);
}

#[tokio::test]
async fn does_not_retry_admin_api_4xx() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    admin.fail_connect_settings(&[403]);
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            Error::Api {
                retryable: false,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(admin.calls(|c| c.connect_settings), 1);
}

#[tokio::test]
async fn lazy_refresh_renews_certificate_that_expires_soon() {
    let mut instance = instance();
    // Less than the four minute refresh buffer, so each connect refreshes.
    instance.client_cert_validity = Duration::from_secs(3 * 60);
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    for _ in 0..2 {
        let mut stream = connector
            .connect(&instance.connection_name())
            .await
            .unwrap();
        ping(&mut stream).await;
    }
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 2);
}

#[tokio::test]
async fn lazy_refresh_reuses_valid_certificate() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    for _ in 0..2 {
        let mut stream = connector
            .connect(&instance.connection_name())
            .await
            .unwrap();
        ping(&mut stream).await;
    }
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 1);
}

#[tokio::test]
async fn refresh_ahead_connects() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| {
        b.refresh_strategy(RefreshStrategy::RefreshAhead)
    })
    .await;

    let mut stream = connector
        .connect(&instance.connection_name())
        .await
        .unwrap();
    ping(&mut stream).await;
}

#[derive(Debug)]
struct FakeIamToken;

impl CredentialsProvider for FakeIamToken {
    async fn headers(
        &self,
        _extensions: Extensions,
    ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
        Ok(CacheableResource::New {
            entity_tag: EntityTag::new(),
            data: HeaderMap::new(),
        })
    }

    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

impl AccessTokenCredentialsProvider for FakeIamToken {
    async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
        Ok(AccessToken {
            token: "fake-iam-token".into(),
        })
    }
}

#[tokio::test]
async fn iam_authn_sends_login_token() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let connector = connector(&admin, |b| {
        b.iam_authn(true)
            .iam_login_credentials(AccessTokenCredentials::from(FakeIamToken))
    })
    .await;

    connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap();
    assert_eq!(
        admin.calls(|c| c.access_token.clone()).as_deref(),
        Some("fake-iam-token")
    );
}

#[tokio::test]
async fn no_login_token_without_iam_authn() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let connector = connector(&admin, |b| b).await;

    connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap();
    assert_eq!(admin.calls(|c| c.access_token.clone()), None);
}

/// An IAM login token that changes when the test calls `rotate`.
#[derive(Clone, Debug, Default)]
struct RotatingIamToken(Arc<AtomicUsize>);

impl RotatingIamToken {
    fn rotate(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl CredentialsProvider for RotatingIamToken {
    async fn headers(
        &self,
        _extensions: Extensions,
    ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
        Ok(CacheableResource::New {
            entity_tag: EntityTag::new(),
            data: HeaderMap::new(),
        })
    }

    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

impl AccessTokenCredentialsProvider for RotatingIamToken {
    async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
        Ok(AccessToken {
            token: format!("token-{}", self.0.load(Ordering::SeqCst)),
        })
    }
}

#[tokio::test]
async fn new_iam_token_refreshes_certificate() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let token = RotatingIamToken::default();
    let connector = connector(&admin, |b| {
        b.iam_authn(true)
            .iam_login_credentials(AccessTokenCredentials::from(token.clone()))
    })
    .await;
    let name = instance.connection_name();

    for _ in 0..2 {
        ping(&mut connector.connect(&name).await.unwrap()).await;
    }
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 1);

    token.rotate();
    ping(&mut connector.connect(&name).await.unwrap()).await;
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 2);
    assert_eq!(
        admin.calls(|c| c.access_token.clone()).as_deref(),
        Some("token-1")
    );
}

/// `TestRefreshRetries50xResponses` for `generateEphemeralCert`.
#[tokio::test]
async fn retries_ephemeral_cert_5xx() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    admin.fail_ephemeral_cert(&[500]);
    let connector = connector(&admin, |b| b).await;

    connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap();
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 2);
}

/// `TestRefreshWithFailedEphemeralCertCall`.
#[tokio::test]
async fn does_not_retry_ephemeral_cert_4xx() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    admin.fail_ephemeral_cert(&[403]);
    let connector = connector(&admin, |b| b).await;

    let error = connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            Error::Api {
                retryable: false,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 1);
}

#[derive(Debug)]
struct FailingIamToken;

impl CredentialsProvider for FailingIamToken {
    async fn headers(
        &self,
        _extensions: Extensions,
    ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
        Err(CredentialsError::from_msg(true, "fake token error"))
    }

    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

impl AccessTokenCredentialsProvider for FailingIamToken {
    async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
        Err(CredentialsError::from_msg(true, "fake token error"))
    }
}

/// `TestRefreshWithIAMAuthErrors`.
#[tokio::test]
async fn iam_token_error_is_retryable_auth_error() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let connector = connector(&admin, |b| {
        b.iam_authn(true)
            .iam_login_credentials(AccessTokenCredentials::from(FailingIamToken))
    })
    .await;

    let error = connector
        .engine_version(&instance.connection_name())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Auth(_)), "{error}");
    assert!(error.is_retryable());
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 0);
}

/// `TestDialerChecksSubjectAlternativeNameAndFallsBackToCN`.
#[tokio::test]
async fn falls_back_to_common_name_when_no_san_matches() {
    let mut instance = instance().with_dns_name("abc.my-region.sql.goog");
    instance.server_name = ServerName::LegacyCn("my-project:my-instance".into());
    let (admin, instance) = FakeAdminApi::start(instance).await;
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    ping(
        &mut connector
            .connect(&instance.connection_name())
            .await
            .unwrap(),
    )
    .await;
}

/// `TestDialerRefreshesAfterRotateCACerts` and `TestDialerRemovesInvalidInstancesFromCache`:
/// after a CA rotation the handshake fails and the instance leaves the cache. The next
/// connect gets the new CA and works.
#[tokio::test]
async fn ca_rotation_evicts_instance_and_next_connect_works() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    let proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;
    let name = instance.connection_name();
    ping(&mut connector.connect(&name).await.unwrap()).await;

    let rotated = admin.set_instance(instance.with_new_ca());
    drop(proxy);
    let _proxy = FakeServerProxy::start(&rotated, Backend::Echo).await;

    let error = connector.connect(&name).await.unwrap_err();
    assert!(matches!(error, Error::Handshake { .. }), "{error}");

    ping(&mut connector.connect(&name).await.unwrap()).await;
    assert_eq!(admin.calls(|c| c.connect_settings), 2);
}

/// `TestDialRefreshesExpiredCertificates` in lazy mode.
#[tokio::test]
async fn lazy_refreshes_expired_certificate() {
    let (admin, instance) = FakeAdminApi::start(instance()).await;
    admin.next_cert_validities(&[-60]);
    let _proxy = FakeServerProxy::start(&instance, Backend::Echo).await;
    let connector = connector(&admin, |b| b).await;

    ping(
        &mut connector
            .connect(&instance.connection_name())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(admin.calls(|c| c.ephemeral_cert), 2);
}
