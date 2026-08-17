"""psycopg driver matrix (milestone 10), driven by `e2e_psycopg.rs`.

The Rust suite provisions the schema, launches the proxy and runs this script;
everything here talks to that already-running proxy over TLS. The Python
drivers cover wire shapes the Rust ones do not:

  * psycopg 3 server-side binding — the *unnamed* prepared statement, since
    libpq's PQsendQueryParams sends Parse ""/Bind "" per execution rather than
    the named statements tokio-postgres and sqlx use.
  * psycopg 3 prepared + binary results — named statements, binary DataRows.
  * psycopg 3 client-side binding and psycopg 2 — literals interpolated into
    the SQL, with bytes rendered as `'\\x…'::bytea`, so the rewrite has to see
    through the cast and the hex.

Environment:
  DBSEC_PROXY_CONNINFO  libpq conninfo for the proxy hop (TLS, verify-full)
  DBSEC_DIRECT_DSN      DSN straight to Postgres, for at-rest assertions
  DBSEC_TABLE           table to use
"""

import os
import sys

import psycopg
import psycopg2

PROXY = os.environ["DBSEC_PROXY_CONNINFO"]
DIRECT = os.environ["DBSEC_DIRECT_DSN"]
TABLE = os.environ["DBSEC_TABLE"]


def masked(note):
    """The note column's read-path mask: keep_first = 2, the rest starred."""
    return note[:2] + "*" * (len(note) - 2)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def psycopg3_server_side_binding(direct):
    """Unnamed prepared statements: Parse ""/Bind "" on every execution."""
    with psycopg.connect(PROXY) as conn, conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {TABLE} (email, phone, ssn, note) VALUES (%s, %s, %s, %s)",
            (b"grace@example.com", "555-101-2020", "078-05-1120", "grace-note"),
        )
        conn.commit()

        cur.execute(f"SELECT email, phone, ssn, note FROM {TABLE} WHERE id = 1")
        email, phone, ssn, note = cur.fetchone()
        check(bytes(email) == b"grace@example.com", f"email not decrypted: {email!r}")
        check(phone == "555-101-2020", f"phone not detokenized: {phone!r}")
        check(len(ssn) == 64, f"token should be a 64-char hex HMAC: {ssn!r}")
        check(note == masked("grace-note"), f"note not masked: {note!r}")

        # Searchable equality through a bound parameter.
        cur.execute(f"SELECT id FROM {TABLE} WHERE email = %s", (b"grace@example.com",))
        check(len(cur.fetchall()) == 1, "blind-index equality found no row")
        cur.execute(f"SELECT id FROM {TABLE} WHERE email = %s", (b"nobody@example.com",))
        check(cur.fetchall() == [], "blind-index equality matched a missing row")

    with direct.cursor() as cur:
        cur.execute(f"SELECT email, phone, ssn, note FROM {TABLE} WHERE id = 1")
        email, phone, ssn, note = cur.fetchone()
        check(bytes(email)[32:36] == b"DBS2", "stored value is not blind index + envelope")
        check(phone != "555-101-2020" and len(phone) == 12, f"FPE at rest wrong: {phone!r}")
        check(len(ssn) == 64, f"token at rest wrong: {ssn!r}")
        check(note == "grace-note", "mask-only column should stay plaintext at rest")


def psycopg3_prepared_and_binary(direct):
    """Named prepared statements, then the same rows read back in binary."""
    with psycopg.connect(PROXY) as conn:
        with conn.cursor() as cur:
            for email, phone in [
                (b"heidi@example.com", "555-303-4040"),
                (b"ivan@example.com", "555-505-6060"),
            ]:
                cur.execute(
                    f"INSERT INTO {TABLE} (email, phone, note) VALUES (%s, %s, %s)",
                    (email, phone, "prepared"),
                    prepare=True,
                )
            conn.commit()

        # binary=True asks for binary DataRows for every column.
        with conn.cursor(binary=True) as cur:
            cur.execute(
                f"SELECT email, phone, note FROM {TABLE} WHERE email = %s",
                (b"heidi@example.com",),
                prepare=True,
            )
            email, phone, note = cur.fetchone()
            check(bytes(email) == b"heidi@example.com", f"binary read wrong: {email!r}")
            check(phone == "555-303-4040", f"binary FPE read wrong: {phone!r}")
            check(note == masked("prepared"), f"binary mask wrong: {note!r}")

    with direct.cursor() as cur:
        cur.execute(f"SELECT email FROM {TABLE} WHERE note = 'prepared' ORDER BY id")
        for (email,) in cur.fetchall():
            check(bytes(email)[32:36] == b"DBS2", "prepared insert stored plaintext")


def psycopg3_client_side_binding(direct):
    """ClientCursor interpolates literals: `'\\x…'::bytea` for bytes."""
    with psycopg.connect(PROXY) as conn, psycopg.ClientCursor(conn) as cur:
        cur.execute(
            f"INSERT INTO {TABLE} (email, phone, note) VALUES (%s, %s, %s)",
            (b"judy@example.com", "555-707-8080", "client-side"),
        )
        conn.commit()

        cur.execute(f"SELECT email, phone FROM {TABLE} WHERE email = %s", (b"judy@example.com",))
        rows = cur.fetchall()
        check(len(rows) == 1, "interpolated blind-index equality found no row")
        check(bytes(rows[0][0]) == b"judy@example.com", f"read wrong: {rows[0][0]!r}")
        check(rows[0][1] == "555-707-8080", f"FPE read wrong: {rows[0][1]!r}")

    with direct.cursor() as cur:
        cur.execute(f"SELECT email, phone FROM {TABLE} WHERE note = 'client-side'")
        email, phone = cur.fetchone()
        check(bytes(email)[32:36] == b"DBS2", "client-side binding stored plaintext")
        check(phone != "555-707-8080", "client-side binding stored the phone in the clear")


def psycopg2_client_side_binding(direct):
    """psycopg 2 always interpolates, and reads results in text format."""
    with psycopg2.connect(PROXY) as conn, conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {TABLE} (email, phone, ssn, note) VALUES (%s, %s, %s, %s)",
            (psycopg2.Binary(b"karl@example.com"), "555-909-1010", "219-09-9999", "psycopg2"),
        )
        conn.commit()

        # Text result format: the BYTEA column comes back `\x` hex encoded and
        # psycopg2 turns it into a memoryview.
        cur.execute(f"SELECT email, phone, ssn, note FROM {TABLE} WHERE email = %s",
                    (psycopg2.Binary(b"karl@example.com"),))
        rows = cur.fetchall()
        check(len(rows) == 1, "psycopg2 blind-index equality found no row")
        email, phone, ssn, note = rows[0]
        check(bytes(email) == b"karl@example.com", f"psycopg2 read wrong: {bytes(email)!r}")
        check(phone == "555-909-1010", f"psycopg2 FPE read wrong: {phone!r}")
        check(len(ssn) == 64, f"psycopg2 token read wrong: {ssn!r}")
        check(note == masked("psycopg2"), f"psycopg2 mask wrong: {note!r}")

    with direct.cursor() as cur:
        cur.execute(f"SELECT email, phone FROM {TABLE} WHERE note = 'psycopg2'")
        email, phone = cur.fetchone()
        check(bytes(email)[32:36] == b"DBS2", "psycopg2 stored plaintext")
        check(phone != "555-909-1010", "psycopg2 stored the phone in the clear")


def main():
    direct = psycopg2.connect(DIRECT)
    cases = [
        psycopg3_server_side_binding,
        psycopg3_prepared_and_binary,
        psycopg3_client_side_binding,
        psycopg2_client_side_binding,
    ]
    for case in cases:
        case(direct)
        direct.rollback()  # keep the read-only snapshot fresh between cases
        print(f"ok   {case.__name__}")
    print(f"psycopg {psycopg.__version__} / psycopg2 {psycopg2.__version__}: all cases passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as failure:
        print(f"FAIL {failure}", file=sys.stderr)
        sys.exit(1)
