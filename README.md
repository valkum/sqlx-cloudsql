# sqlx-cloudsql

An experiment: connect sqlx pools to Google Cloud SQL the way the
[Go connector](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector) does.
On each new connection, the pool gets a fresh ephemeral certificate (and IAM token)
and opens a TLS 1.3 connection to the instance on port 3307.

The connector logic is ported from the Go connector: the refresh timing, the
server certificate check and the connect steps. The MySQL parts are ported over from
the Go connector and the Go MySQL driver, which encrypts the password with the RSA key
of the server. So the `mysql` feature enables the sqlx `mysql-rsa` feature.

Features: `postgres` and `mysql`. Both are enabled by default.

This crate needs a patched sqlx that is not released. The crate uses it from the fork
[valkum/sqlx](https://github.com/valkum/sqlx), branch `dev/cloudsql`. The patch adds:

- `PoolOptions::connector`, a hook that opens each pool connection
  (based on launchbadge/sqlx#3582).
- `PgConnection::connect_raw_tokio` and `MySqlConnection::connect_raw_tokio`, which run
  the database protocol over a stream that you supply (from launchbadge/sqlx#4281).

Do not use it in production.
