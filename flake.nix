{
  description = "gitle: a git server that lives on your tailnet";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems =
        [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in
    {
      overlay = final: prev: {
        inherit (self.packages.${prev.system}) gitle;
      };
      packages = forAllSystems (system:
        let pkgs = nixpkgsFor.${system};
        in {
          gitle = pkgs.buildGo123Module {
            pname = "gitle";
            version = "v1.0.3";
            src = ./.;

            vendorHash = "sha256-6ZrOe2U/YanW9mDRuj9npaYbof0TuzXg11lT3k/Kx7w=";
          };
        });

      defaultPackage = forAllSystems (system: self.packages.${system}.gitle);
      devShells = forAllSystems (system:
        let pkgs = nixpkgsFor.${system};
        in {
          default = pkgs.mkShell {
            shellHook = ''
              PS1='\u@\h:\@; '
              echo "Go `${pkgs.go}/bin/go version`"
            '';
            nativeBuildInputs = with pkgs; [
              git
              go
              gopls
              go-tools
            ];
          };
        });
    };
}
