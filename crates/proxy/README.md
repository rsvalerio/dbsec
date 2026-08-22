# dbsec

A transparent PostgreSQL proxy that applies field-level encryption on the wire:
it seals values in `INSERT`/`UPDATE`, rewrites equality predicates over
searchable columns to their blind index, and opens and masks result columns —
for applications that cannot be changed to call a library.

```
cargo install dbsec
dbsec /etc/dbsec/dbsec.toml
```

If you *can* change the application, prefer
[`dbsec-core`](https://crates.io/crates/dbsec-core): it does the same work at
code time, writes the identical stored format, and sees things a proxy cannot.
The two interoperate on one table.

Configuration, the `on_unprotected` switch, row binding, and the deployment
notes are in the [repository README](https://github.com/rsvalerio/dbsec).

License: Apache-2.0.
