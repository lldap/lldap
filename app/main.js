import init, { run_app } from './pkg/lldap_app.js';
async function main() {
   await init('/pkg/lldap_app_bg.wasm');
   run_app();
}
main()
