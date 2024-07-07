{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    # nativeBuildInputs is usually what you want -- tools you need to run
    nativeBuildInputs = with pkgs.buildPackages; [ 
      gcc-arm-embedded
      gnumake
      ((qemu.override {
        hostCpuTargets=["arm-softmmu"];
        }).overrideAttrs(a: {
          patches = a.patches ++ [
            ./qemu.patch
          ];
        }))
     ];
}