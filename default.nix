{ pkgs ? import <nixpkgs> { overlays = import ./overlays.nix; } }:
let
  overrides = import ./overrides.nix { inherit pkgs; };
in
pkgs.poetry2nix.mkPoetryApplication {
  projectDir = ./.;
  python = pkgs.python3;
  overrides = pkgs.poetry2nix.overrides.withDefaults overrides;
  meta.description = "Nix package for ${pkgs.stdenv.system}";
}
