# dbsec-pgwire

Sans-io framing for the PostgreSQL v3 wire protocol: it turns a byte stream
into messages and back, and does no I/O of its own.

Extracted from the [`dbsec`](https://github.com/rsvalerio/dbsec) proxy, which
needs to read and rewrite frames mid-flight. It is published because it is
independently useful, not because it aims to be a complete PostgreSQL client —
it knows message framing and the format codes, and nothing about connections,
authentication or types.

`unsafe_code = "forbid"`.

License: Apache-2.0.
