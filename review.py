#!/usr/bin/env python3
"""Update a manual review decision in the report database."""
import argparse
import sqlite3

STATES = ("unreviewed", "investigating", "false_positive", "reported")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Exact URL from the report")
    parser.add_argument("--status", required=True, choices=STATES)
    parser.add_argument("--owner", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--database", default="reports/recon_history.db")
    args = parser.parse_args(argv)
    with sqlite3.connect(args.database) as conn:
        if not conn.execute("SELECT 1 FROM master_urls WHERE url=?", (args.url,)).fetchone():
            parser.error("URL not found in report history")
        conn.execute("CREATE TABLE IF NOT EXISTS endpoint_reviews (url TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'unreviewed', owner TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '')")
        conn.execute("INSERT INTO endpoint_reviews(url,status,owner,note) VALUES(?,?,?,?) ON CONFLICT(url) DO UPDATE SET status=excluded.status,owner=excluded.owner,note=excluded.note",
                     (args.url, args.status, args.owner, args.note))
    print("Review saved. Rebuild the report to display the updated state.")


if __name__ == "__main__":
    main()
