{ pkgs ? import <nixpkgs> {} }:
# https://github.com/NixOS/nixpkgs/blob/nixos-unstable/pkgs/by-name/ch/ch341eeprom/package.nix#L35
# not on my version of nixos so yeha... 
let ch341eeprom = with pkgs; stdenv.mkDerivation {
  pname = "ch341eeprom";
  version = "0-unstable-2024-05-06";

  src = fetchFromGitHub {
    owner = "command-tab";
    repo = "ch341eeprom";
    rev = "7cffbef7552d93162bd90cae836a45e94acb93fb";
    hash = "sha256-8pvQ2hBP3Rf8+MWsmMY53BghFiC5/b9k8vUjU2K6Ib4=";
  };

  buildInputs = [ libusb1 ];

  makeFlags = [ "CC=${stdenv.cc.targetPrefix}cc" ];

  installPhase = ''
    runHook preInstall
    install -Dm755 -T ch341eeprom $out/bin/ch341eeprom
    runHook postInstall
  '';

  passthru = {
    updateScript = unstableGitUpdater { hardcodeZeroVersion = true; };
  };

  meta = {
    description = "Libusb based programming tool for 24Cxx serial EEPROMs using the WinChipHead CH341A IC";
    homepage = "https://github.com/command-tab/ch341eeprom";
    license = lib.licenses.gpl3Plus;
    mainProgram = "ch341eeprom";
    maintainers = with lib.maintainers; [ xokdvium ];
    platforms = with lib.platforms; darwin ++ linux;
  };
};
in pkgs.mkShell {
    # nativeBuildInputs is usually what you want -- tools you need to run
    nativeBuildInputs = with pkgs.buildPackages; [ flashrom ch341eeprom ];
}