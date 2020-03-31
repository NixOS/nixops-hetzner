{ nixpkgs ? <nixpkgs> }:
let
  overlays = import ./overlays.nix;
  overrides = import ./overrides.nix;
  pkgs = import nixpkgs {
    system = "x86_64-linux";
    inherit overlays;
  };
in
{
  build = pkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "x86_64-darwin" ] (
    system:
      with import nixpkgs { inherit system; inherit overlays; };
      poetry2nix.mkPoetryApplication {
        projectDir = ./.;
        python = python3;

        meta.description = "Nix package for ${stdenv.system}";

        overrides = poetry2nix.overrides.withDefaults overrides;
      }
  );
}
