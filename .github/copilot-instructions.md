# LLDAP - Light LDAP implementation for authentication

LLDAP is a lightweight LDAP authentication server written in Rust with a WebAssembly frontend. It provides an opinionated, simplified LDAP interface for authentication and integrates with many popular services.

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### Bootstrap and Build the Repository
- Install dependencies: `sudo apt-get update && sudo apt-get install -y curl gzip binaryen`
- Install Rust if not available: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` then `source ~/.cargo/env`
- Install wasm-pack for frontend: `cargo install wasm-pack` -- takes 90 seconds. NEVER CANCEL. Set timeout to 180+ seconds.
- Build entire workspace: `cargo build --workspace` -- takes 3-4 minutes. NEVER CANCEL. Set timeout to 300+ seconds.
- Build release server binary: `cargo build --release -p lldap` -- takes 5-6 minutes. NEVER CANCEL. Set timeout to 420+ seconds.
- Build frontend WASM: `./app/build.sh` -- takes 3-4 minutes including wasm-pack installation. NEVER CANCEL. Set timeout to 300+ seconds.

### Testing and Validation
- Run all tests: `cargo test --workspace` -- takes 2-3 minutes. NEVER CANCEL. Set timeout to 240+ seconds.
- Check formatting: `cargo fmt --all --check` -- takes <5 seconds.
- Run linting: `cargo clippy --tests --all -- -D warnings` -- takes 60-90 seconds. NEVER CANCEL. Set timeout to 120+ seconds.
- Export GraphQL schema: `./export_schema.sh` -- takes 70-80 seconds. NEVER CANCEL. Set timeout to 120+ seconds.

### Running the Application
- **ALWAYS run the build steps first before starting the server.**
- Start development server: `cargo run -- run --config-file <config_file>`
- **CRITICAL**: Server requires a valid configuration file. Use `lldap_config.docker_template.toml` as reference.
- **CRITICAL**: Avoid key conflicts by removing existing `server_key*` files when testing with `key_seed` in config.
- Server binds to:
  - LDAP: port 3890 (configurable)
  - Web interface: port 17170 (configurable)
  - LDAPS: port 6360 (optional, disabled by default)

### Manual Validation Requirements
- **ALWAYS test both LDAP and web interfaces after making changes.**
- Test web interface: `curl -s http://localhost:17170/` should return HTML with "LLDAP Administration" title.
- Test GraphQL API: `curl -s -X POST -H "Content-Type: application/json" -d '{"query": "query { __schema { queryType { name } } }"}' http://localhost:17170/api/graphql`
- Run healthcheck: `cargo run -- healthcheck --config-file <config_file>` (requires running server)
- **ALWAYS ensure server starts without errors and serves the web interface before considering changes complete.**

## Validation Scenarios

After making code changes, ALWAYS:
1. **Build validation**: Run `cargo build --workspace` to ensure compilation succeeds.
2. **Test validation**: Run `cargo test --workspace` to ensure existing functionality works.
3. **Lint validation**: Run `cargo clippy --tests --all -- -D warnings` to catch potential issues.
4. **Format validation**: Run `cargo fmt --all --check` to ensure code style compliance.
5. **Frontend validation**: Run `./app/build.sh` to ensure WASM compilation succeeds.
6. **Runtime validation**: Start the server and verify web interface accessibility.
7. **Schema validation**: If GraphQL changes made, run `./export_schema.sh` to update schema.

### Test User Scenarios
- **Login flow**: Access web interface at `http://localhost:17170`, attempt login with admin/password (default).
- **LDAP binding**: Test LDAP connection on port 3890 with appropriate LDAP tools if available.
- **Configuration changes**: Test with different configuration files to validate config parsing.

## Project Structure and Key Components

### Backend (Rust)
- **Server**: `/server` - Main application binary
- **Crates**: `/crates/*` - Modularized components:
  - `auth` - Authentication and OPAQUE protocol
  - `domain*` - Domain models and handlers  
  - `ldap` - LDAP protocol implementation
  - `graphql-server` - GraphQL API server
  - `sql-backend-handler` - Database operations
  - `validation` - Input validation utilities

### Frontend (Rust + WASM)
- **App**: `/app` - Yew-based WebAssembly frontend
- **Build**: `./app/build.sh` - Compiles Rust to WASM using wasm-pack
- **Assets**: `/app/static` - Static web assets

### Configuration and Deployment
- **Config template**: `lldap_config.docker_template.toml` - Reference configuration
- **Docker**: `Dockerfile` - Container build definition
- **Scripts**: 
  - `prepare-release.sh` - Cross-platform release builds
  - `export_schema.sh` - GraphQL schema export
  - `generate_secrets.sh` - Random secret generation
  - `scripts/bootstrap.sh` - User/group management script

## Common Development Workflows

### Making Backend Changes
1. Edit Rust code in `/server` or `/crates`
2. Run `cargo build --workspace` to test compilation
3. Run `cargo test --workspace` to ensure tests pass
4. Run `cargo clippy --tests --all -- -D warnings` to check for warnings
5. If GraphQL schema affected, run `./export_schema.sh`
6. Test by running server and validating functionality

### Making Frontend Changes  
1. Edit code in `/app/src`
2. Run `./app/build.sh` to rebuild WASM package
3. Start server and test web interface functionality
4. Verify no JavaScript errors in browser console

### Adding New Dependencies
- Backend: Add to appropriate `Cargo.toml` in `/server` or `/crates/*`
- Frontend: Add to `/app/Cargo.toml`
- **Always rebuild after dependency changes**

## CI/CD Integration

The repository uses GitHub Actions (`.github/workflows/rust.yml`):
- **Build job**: Validates workspace compilation
- **Test job**: Runs full test suite  
- **Clippy job**: Linting with warnings as errors
- **Format job**: Code formatting validation
- **Coverage job**: Code coverage analysis

**ALWAYS ensure your changes pass all CI checks by running equivalent commands locally.**

## Timing Expectations and Timeouts

| Command | Expected Time | Timeout Setting |
|---------|---------------|-----------------|
| `cargo build --workspace` | 3-4 minutes | 300+ seconds |
| `cargo build --release -p lldap` | 5-6 minutes | 420+ seconds |
| `cargo test --workspace` | 2-3 minutes | 240+ seconds |
| `./app/build.sh` | 3-4 minutes | 300+ seconds |
| `cargo clippy --tests --all -- -D warnings` | 60-90 seconds | 120+ seconds |
| `./export_schema.sh` | 70-80 seconds | 120+ seconds |
| `cargo install wasm-pack` | 90 seconds | 180+ seconds |

**NEVER CANCEL** any of these commands. Builds may take longer on slower systems.

## Troubleshooting Common Issues

### Build Issues
- **Missing wasm-pack**: Run `cargo install wasm-pack`
- **Missing binaryen**: Run `sudo apt-get install -y binaryen` or disable wasm-opt
- **Clippy warnings**: Fix all warnings as they are treated as errors in CI
- **GraphQL schema mismatch**: Run `./export_schema.sh` to update schema

### Runtime Issues
- **Key conflicts**: Remove `server_key*` files when using `key_seed` in config
- **Port conflicts**: Check if ports 3890/17170 are available
- **Database issues**: Ensure database URL in config is valid and accessible
- **Asset missing**: Ensure frontend is built with `./app/build.sh`

### Development Environment
- **Rust version**: Use stable Rust toolchain (2024 edition)
- **System dependencies**: curl, gzip, build tools
- **Database**: SQLite (default), MySQL, or PostgreSQL supported

## Configuration Reference

Essential configuration parameters:
- `ldap_base_dn`: LDAP base DN (e.g., "dc=example,dc=com")
- `ldap_user_dn`: Admin user DN 
- `ldap_user_pass`: Admin password
- `jwt_secret`: Secret for JWT tokens (generate with `./generate_secrets.sh`)
- `key_seed`: Encryption key seed
- `database_url`: Database connection string
- `http_port`: Web interface port (default: 17170)
- `ldap_port`: LDAP server port (default: 3890)

**Always use the provided config template as starting point for new configurations.**