{
  description = "clusterFUQ";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        }; in
        {
          devShells.default = with pkgs; mkShell {
            buildInputs = [
              cmake
              gcc-arm-embedded
              newlib

              python3
              python3Packages.regex
              python3Packages.cbor2
              python3Packages.pyyaml
              python3Packages.pyelftools

              openocd

              probe-rs
              flip-link
              (rust-bin.nightly.latest.default.override {
                extensions = [ "rust-src"];
                targets = [ "thumbv6m-none-eabi" ];
              })
            ];
          };
        }
      );
}