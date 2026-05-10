{
  description = "Minimal TTY login greeter written in Crystal";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Linux-only tool — hard-pin to x86_64-linux.
      system = "x86_64-linux";
      pkgs   = nixpkgs.legacyPackages.${system};
      lib    = nixpkgs.lib;
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

      # ── NixOS VM for isolated testing ───────────────────────────────────
      # Build + run with:  nix run .#vm
      # Or manually:       nix build .#nixosConfigurations.vm.config.system.build.vm
      #                    ./result/bin/run-greeter-test-vm
      #
      # Test credentials:  user=test  password=test
      nixosConfigurations.vm = lib.nixosSystem {
        inherit system;
        modules = [
          ({ config, pkgs, ... }: {
            system.stateVersion = "24.11";

            # Minimal bootloader (not needed for VM but required by NixOS)
            boot.loader.grub.device = "nodev";

            networking.hostName = "greeter-test";

            # Test user — password is "test"
            users.users.test = {
              isNormalUser = true;
              initialPassword = "test";
              extraGroups = [ "video" "input" ];
            };

            # Ensure share/xsessions from installed WM packages gets linked
            # into /run/current-system/sw/share/xsessions/ so the greeter
            # can find the .desktop files.
            environment.pathsToLink = [ "/share/xsessions" ];

            # Packages available in the VM session.
            # WM packages ship share/xsessions/*.desktop files; installing them
            # here makes those files appear under
            # /run/current-system/sw/share/xsessions/ — exactly where the
            # greeter scans for sessions.
            environment.systemPackages = with pkgs; [
              fvwm3
              openbox
              xinit
              xorg-server
              xrandr
              rxvt-unicode
              openssh
            ];

            # Allow SSH connections for testing the SSH menu option
            services.openssh.enable = true;

            # Install the greeter as a setuid-root wrapper
            security.wrappers.crystal-greeter = {
              source = "${self.packages.${system}.default}/bin/crystal-greeter";
              owner  = "root";
              group  = "root";
              setuid = true;
            };

            # Replace getty on tty1 with the greeter
            systemd.services."getty@tty1".enable   = false;
            systemd.services."autovt@tty1".enable  = false;
            systemd.services.crystal-greeter = {
              description = "Crystal TTY greeter";
              after       = [ "systemd-user-sessions.service" ];
              wantedBy    = [ "multi-user.target" ];
              conflicts   = [ "getty@tty1.service" ];
              serviceConfig = {
                ExecStart      = "/run/wrappers/bin/crystal-greeter";
                StandardInput  = "tty";
                StandardOutput = "tty";
                TTYPath        = "/dev/tty1";
                TTYReset       = true;
                TTYVHangup     = true;
                Restart        = "always";
                RestartSec     = "1s";
              };
            };

          })
        ];
      };

      apps.${system}.vm = {
        type    = "app";
        program = "${self.nixosConfigurations.vm.config.system.build.vm}/bin/run-greeter-test-vm";
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
          pkgs.crystalline  # Crystal LSP server
          pkgs.pkg-config   # needed by crystalline to resolve lib flags
        ];

        shellHook = ''
          echo ""
          echo "  crystal-greeter dev shell"
          echo "  ─────────────────────────────────────────"
          echo "  make debug    fast debug build  → ./greeter"
          echo "  make build    release build     → ./greeter"
          echo "  make install  install setuid-root to /usr/local/bin"
          echo "  nix build     build via Nix     → ./result/bin/crystal-greeter"
          echo "  nix run .#vm  run a vm to test the greeter"
          echo ""
        '';
      };
    };
}
