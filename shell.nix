{ nixpkgs ? <nixpkgs> }:
let
  overlays = import ./overlays.nix;
  pkgs = import nixpkgs { inherit overlays; };
  overrides = import ./overrides.nix { inherit pkgs; };
in
pkgs.mkShell {
  buildInputs = [
    (
      pkgs.poetry2nix.mkPoetryEnv {
        projectDir = ./.;
        overrides = pkgs.poetry2nix.overrides.withDefaults overrides;
      }
    )
    pkgs.poetry
  ];
}
