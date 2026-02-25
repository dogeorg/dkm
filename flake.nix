{
  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go_1_25
          ];
        };

        packages = rec {
          dkm = pkgs.buildGoModule {
            name = "dkm";
            src = ./.;

            vendorHash = "sha256-9smxGxt+XHXc6KZnGxCQ9SlFGPu7BmsLATV/O4fybFU=";

            buildPhase = "make";

            nativeBuildInputs = [ pkgs.go_1_25 ];
            buildInputs = [];

            installPhase = ''
              mkdir -p $out/bin
              cp dkm $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "Doge Key Manager";
              homepage = "https://github.com/Dogebox-WG/dkm";
              license = licenses.mit;
              maintainers = with maintainers; [ dogecoinfoundation ];
              platforms = platforms.all;
            };
          };

          default = dkm;
        };

        dbxSessionName = "dkm";
        dbxStartCommand = "make dev";
      }
    );
}
