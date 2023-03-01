{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    go_1_20
  ];
}
