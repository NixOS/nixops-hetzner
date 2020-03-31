[
  (
    # FIXME: we should not have to use a custom version of poetry2nix. Given
    # enough time the version in nixpkgs-unstable should be recent enough
    self: super: {
      poetry2nix = self.callPackage (
        self.fetchFromGitHub {
          owner = "nix-community";
          repo = "poetry2nix";
          rev = "1158541d5f510e736358ea00b28b059e7462b635";
          sha256 = "1f56hyqcfjx636633mqzy6skpc0x2jgh6g0zy2vagkz94fpy4sbw";
        }
      ) {};
    }
  )
]
