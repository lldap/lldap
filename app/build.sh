#! /bin/sh

cd $(dirname $0)
wasm-pack build --target web
../node_modules/rollup/dist/bin/rollup ./main.js --format iife --file ./pkg/bundle.js
