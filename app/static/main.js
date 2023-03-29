import init, { run_app } from '/pkg/lldap_app.js';
async function main() {
  if(navigator.userAgent.indexOf('AppleWebKit') != -1) {
    await init('/pkg/lldap_app_bg.wasm');
  } else {
    await init('/pkg/lldap_app_bg.wasm.gz');
  }
  run_app();
}
main()
