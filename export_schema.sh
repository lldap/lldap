#! /bin/sh

cd $(dirname $(readlink -f "$0"))

cargo run -- export_graphql_schema -o schema.graphql
