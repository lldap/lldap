# Migration

Existing servers can migrate from one database backend to another. This page includes guidance for migrating from SQLite - similar concepts apply when migrating from databases of other types.

NOTE: [pgloader](https://github.com/dimitri/pgloader) is a tool that can easily migrate to PostgreSQL from other databases. Consider it if your target database is PostgreSQL

The process is as follows:

1. Create empty schema on target database
2. Stop/pause LLDAP and dump existing values
3. Sanitize for target DB (not always required)
4. Insert data into target
5. Change LLDAP config to new target and restart

The steps below assume you already have PostgreSQL or MySQL set up with an empty database for LLDAP to use.

## Create schema on target

LLDAP has a command that will connect to a target database and initialize the
schema. If running with docker, run the following command to use your active
instance (this has the benefit of ensuring your container has access):

```
docker exec -it <LLDAP container name> /app/lldap create_schema -d <Target database url>
```

If it succeeds, you can proceed to the next step.

## Create a dump of existing data

We want to dump (almost) all existing values to some file - the exception being the `metadata` table. Be sure to stop/pause LLDAP during this step, as some
databases (SQLite in this example) will give an error if LLDAP is in the middle of a write. The dump should consist just INSERT
statements. There are various ways to do this, but a simple enough way is filtering a
whole database dump. For example:

```
sqlite3 /path/to/lldap/config/users.db .dump | grep "^INSERT" | grep -v "^INSERT INTO metadata" > /path/to/dump.sql
```

## Sanitize data

Some databases might use different formats for some data - for example, PostgreSQL uses
a different syntax for hex strings than SQLite. We also want to make sure inserts are done in
a transaction in case one of the statements fail.

### To PostgreSQL

PostgreSQL uses a different hex string format. The command below should switch SQLite
format to PostgreSQL format, and wrap it all in a transaction:

```
sed -i -r -e "s/X'([[:xdigit:]]+'[^'])/'\\\x\\1/g" \
-e '1s/^/BEGIN;\n/' \
-e '$aCOMMIT;' /path/to/dump.sql
```

### To MySQL

MySQL mostly cooperates, but it gets some errors if you don't escape the `groups` table. Run the
following command to wrap all table names in backticks for good measure, and wrap the inserts in
a transaction:

```
sed -i -r -e 's/^INSERT INTO ([a-zA-Z0-9_]+) /INSERT INTO `\1` /' \
-e '1s/^/START TRANSACTION;\n/' \
-e '$aCOMMIT;' /path/to/dump.sql
```

## Insert data

Insert the data generated from the previous step into the target database. If you encounter errors,
you may need to manually tweak your dump, or make changed in LLDAP and recreate the dump.

### PostgreSQL

`psql -d <database> -U <username> -W < /path/to/dump.sql`

or 

`psql -d <database> -U <username> -W -f /path/to/dump.sql`

### MySQL

`mysql -u <username> -p <database> < /path/to/dump.sql`

NOTE: MySQL will limit avatar size to 64Kb. You may need to remove avatars for some users. See #486

## Switch to new database

Modify your `database_url` in `lldap_config.toml` (or `LLDAP_DATABASE_URL` in the env)
to point to your new database (the same value used when generating schema). Restart
LLDAP and check the logs to ensure there were no errors.