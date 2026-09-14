{
  description = "Manage CSCS SSH-key certificates";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # fenix provides a rustc/cargo new enough for edition 2024 (rustc >= 1.85).
        toolchain = fenix.packages.${system}.stable.toolchain;

        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };

        cscs-key = pkgs.callPackage ./package.nix { inherit rustPlatform; };
      in
      {
        packages.default = cscs-key;
        packages.cscs-key = cscs-key;

        apps.default = flake-utils.lib.mkApp { drv = cscs-key; } // {
          meta.description = "Manage CSCS SSH-key certificates";
        };

        devShells.default = pkgs.mkShell {
          packages = [ toolchain pkgs.rust-analyzer ];
        };
      });
}
