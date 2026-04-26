{
  description = "Minimal TTY login greeter written in Crystal";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Linux-only tool — hard-pin to x86_64-linux.
      system = "x86_64-linux";
      pkgs   = nixpkgs.legacyPackages.${system};
    in {

      # ── installable package ─────────────────────────────────────────────
      # Build with:  nix build
      # Result at:   ./result/bin/crystal-greeter
      #
      # Install setuid-root for production use:
      #   install -m 4755 -o root result/bin/crystal-greeter /usr/local/bin/
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname   = "crystal-greeter";
        version = "0.1.0";
        src     = ./.;

        nativeBuildInputs = [ pkgs.crystal ];
        buildInputs       = [ pkgs.linux-pam ];

        buildPhase = ''
          crystal build src/greeter.cr -o greeter --release
        '';

        installPhase = ''
          install -Dm755 greeter $out/bin/crystal-greeter
        '';

        meta = with pkgs.lib; {
          description = "Minimal TTY login greeter in Crystal (PAM + fvwm3)";
          license     = licenses.mit;
          platforms   = [ "x86_64-linux" ];
          mainProgram = "crystal-greeter";
        };
      };

      # ── development shell ───────────────────────────────────────────────
      # Enter with:  nix develop
      # Then use:    make debug   (fast build)
      #              make build   (release build)
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.crystal      # compiler + stdlib
          pkgs.shards       # dependency manager (if shards ever get added)
          pkgs.linux-pam    # libpam.so + headers for FFI binding
        ];

        shellHook = ''
          echo ""
          echo "  crystal-greeter dev shell"
          echo "  ─────────────────────────────────────────"
          echo "  make debug    fast debug build  → ./greeter"
          echo "  make build    release build     → ./greeter"
          echo "  make install  install setuid-root to /usr/local/bin"
          echo "  nix build     build via Nix     → ./result/bin/crystal-greeter"
          echo ""
        '';
      };
    };
}
