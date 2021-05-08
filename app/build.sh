#! /bin/sh

cd $(dirname $0)
wasm-pack build --target web
rollup ./main.js --format iife --file ./pkg/bundle.js
