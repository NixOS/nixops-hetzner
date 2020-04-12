{ src ? { outPath = ./.; revCount = 0; shortRev = "abcdef"; rev = "HEAD"; }
, officialRelease ? false
, nixpkgs ? <nixpkgs>
}:

let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  version = "1.7" +
            (if officialRelease then ""
             else if src ? lastModifiedDate then "pre${builtins.substring 0 8 src.lastModifiedDate}.${src.shortRev}"
             else "pre${toString (src.revCount or 0)}_${src.shortRev or "abcdef"}");
in

rec {
  build = pkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "x86_64-darwin" ] (system:
    with import nixpkgs { inherit system; };

    python2Packages.buildPythonApplication rec {
      name = "nixops-hetzner-${version}";
      namePrefix = "";

      src = ./.;

      prePatch = ''
        for i in setup.py; do
          substituteInPlace $i --subst-var-by version ${version}
        done
      '';

      buildInputs = [ python2Packages.nose python2Packages.coverage ];

      propagatedBuildInputs = with python2Packages;
        [
          hetzner
        ];

      # For "nix-build --run-env".
      shellHook = ''
        export PYTHONPATH=$(pwd):$PYTHONPATH
        export PATH=$(pwd)/scripts:${openssh}/bin:$PATH
      '';

      doCheck = false;

      # Needed by libcloud during tests
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

      # Add openssh to nixops' PATH. On some platforms, e.g. CentOS and RHEL
      # the version of openssh is causing errors when have big networks (40+)
      makeWrapperArgs = ["--prefix" "PATH" ":" "${openssh}/bin" "--set" "PYTHONPATH" ":"];

      postInstall =
        ''
          mkdir -p $out/share/nix/nixops-hetzner
          cp -av nix/* $out/share/nix/nixops-hetzner
        '';

      meta.description = "Nix package for ${stdenv.system}";
    }
  );
}
