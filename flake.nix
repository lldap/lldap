{
  description = "LLDAP - Light LDAP implementation for authentication";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # MSRV from the project
        rustVersion = "1.89.0";
        
        # Rust toolchain with required components
        rustToolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
          targets = [ 
            "wasm32-unknown-unknown" 
            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl" 
            "armv7-unknown-linux-musleabihf"
          ];
        };

        craneLib = crane.lib.${system}.overrideToolchain rustToolchain;

        # Common build inputs
        nativeBuildInputs = with pkgs; [
          # Rust toolchain and tools
          rustToolchain
          wasm-pack
          
          # Build tools
          pkg-config
          
          # Compression and utilities
          gzip
          curl
          wget
          
          # Development tools
          git
          jq
          
          # Cross-compilation support
          gcc
        ];

        buildInputs = with pkgs; [
          # System libraries that might be needed
          openssl
          sqlite
        ] ++ lib.optionals stdenv.isDarwin [
          # macOS specific dependencies
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        # Environment variables
        commonEnvVars = {
          CARGO_TERM_COLOR = "always";
          RUST_BACKTRACE = "1";
          
          # Cross-compilation environment
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/cc";
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc}/bin/aarch64-unknown-linux-gnu-gcc";
          CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER = "${pkgs.pkgsCross.armv7l-hf-multiplatform.stdenv.cc}/bin/arm-unknown-linux-gnueabihf-gcc";
        };



      in
      {
        # Development shells
        devShells = {
          default = pkgs.mkShell ({
            inherit nativeBuildInputs buildInputs;
            
            shellHook = ''
              echo "🔐 LLDAP Development Environment"
              echo "==============================================="
              echo "Rust version: ${rustVersion}"
              echo "Standard cargo commands available:"
              echo "  cargo build --workspace    - Build the workspace"
              echo "  cargo test --workspace     - Run tests"
              echo "  cargo clippy --tests --workspace -- -D warnings - Run linting"
              echo "  cargo fmt --check --all    - Check formatting"
              echo "  ./app/build.sh              - Build frontend WASM"
              echo "  ./export_schema.sh          - Export GraphQL schema"
              echo "==============================================="
              echo ""
              
              # Ensure wasm-pack is available
              if ! command -v wasm-pack &> /dev/null; then
                echo "⚠️  wasm-pack not found in PATH"
              fi
              
              # Check if we're in the right directory
              if [[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "$PWD" ]]; then
                echo "⚠️  Run this from the project root directory"
              fi
            '';
          } // commonEnvVars);

          # Minimal shell for CI-like environment
          ci = pkgs.mkShell ({
            inherit nativeBuildInputs buildInputs;
            
            shellHook = ''
              echo "🤖 LLDAP CI Environment"
              echo "Running with Rust ${rustVersion}"
            '';
          } // commonEnvVars);
        };

        # Package outputs (optional - for building with Nix)
        packages = {
          default = craneLib.buildPackage {
            src = craneLib.cleanCargoSource (craneLib.path ./.);
            
            inherit nativeBuildInputs buildInputs;
            
            # Build only the server by default
            cargoExtraArgs = "-p lldap";
            
            # Skip tests in the package build
            doCheck = false;
            
            meta = with pkgs.lib; {
              description = "Light LDAP implementation for authentication";
              homepage = "https://github.com/lldap/lldap";
              license = licenses.gpl3Only;
              maintainers = with maintainers; [ ];
              platforms = platforms.unix;
            };
          };
        };

        # Formatter for the flake itself
        formatter = pkgs.nixpkgs-fmt;

        # Apps for running via `nix run`
        apps = {
          default = flake-utils.lib.mkApp {
            drv = self.packages.${system}.default;
          };
        };
      });
}