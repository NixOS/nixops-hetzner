{ nixpkgs ? <nixpkgs> }:
let
  overlays = import ./overlays.nix;
  inherit (import nixpkgs {}) lib;
in
{
  build = lib.genAttrs [ "x86_64-linux" "i686-linux" "x86_64-darwin" ] (
    system:
      with import nixpkgs { inherit system; inherit overlays; };
      callPackage ./default.nix {}
  );
}
