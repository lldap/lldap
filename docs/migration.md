# Migration

Existing servers can migrate from one database backend to another. This page includes guidance for migrating from sqlite - similar concepts apply when migrating from databases of other types.

NOTE: [pgloader](https://github.com/dimitri/pgloader) is a tool that can easily migrate to postgres from other databases. Consider it if your target database is postgres

The process is as follows:

1. Create a dump of existing data.
2. Change all `CREATE TABLE ...` lines to `DELETE FROM tablename;`. We will later have lldap create the schema for us, so we want to clear out existing data to replace it with the original data.
3. Do any syntax fixes for the target db syntax
4. Change your lldap config database_url to point to the new target and restart.
5. After lldap has started, stop it.
6. Execute the manicured dump file against the new database.

The steps below assume you already have Postgres or MySQL set up with an empty database for lldap to use.

## Create a dump

First, we must dump the existing data to a file. The dump must be tweaked slightly according to your target db. See below for commands

### Postgres

Postgres uses a different hex string format and doesn't support `PRAGMA`.

```
sqlite3 /path/to/lldap/config/users.db .dump | \
sed -r -e "s/X'([[:xdigit:]]+'[^'])/'\\\x\\1/g" \
-e 's/^CREATE TABLE IF NOT EXISTS "([^"]*)".*/DELETE FROM \1;/' \
-e '/^PRAGMA.*/d' > /path/to/dump.sql
```

### MySQL

MySQL doesn't support `PRAGMA`.

```
sqlite3 /path/to/lldap/config/users.db .dump | \
-e 's/^CREATE TABLE IF NOT EXISTS "([^"]*)".*/DELETE FROM \1;/' \
-e '/^PRAGMA.*/d' > /path/to/dump.sql
```

## Generate New Schema

Modify your `database_url` in `lldap_config.toml` (or `LLDAP_DATABASE_URL` in the env) to point to your new database. Restart lldap and check the logs to ensure there were no errors connecting and creating the tables. After that, stop lldap. Now we can import our original data!

### Postgres

`psql -d <database> -U <username> -W < /path/to/dump.sql`

### MySQL

`mysql -u < -p <database> < /path/to/dump.sql`

## Finish

If all succeeds, you're all set to start lldap with your new database!