#! /bin/sh

cd $(dirname $0)
if ! which wasm-pack > /dev/null 2>&1
then
  >&2 echo '`wasm-pack` not found. Try running `cargo install wasm-pack`'
  exit 1
fi

wasm-pack build --target web

ROLLUP_BIN=$(which rollup 2>/dev/null)
if [ -f ../node_modules/rollup/dist/bin/rollup ]
then
  ROLLUP_BIN=../node_modules/rollup/dist/bin/rollup
elif [ -f node_modules/rollup/dist/bin/rollup ]
then
  ROLLUP_BIN=node_modules/rollup/dist/bin/rollup
fi

if [ -z "$ROLLUP_BIN" ]
then
  >&2 echo '`rollup` not found. Try running `npm install rollup`'
  exit 1
fi

$ROLLUP_BIN ./main.js --format iife --file ./pkg/bundle.js --globals bootstrap:bootstrap
