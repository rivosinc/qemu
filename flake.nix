# SPDX-FileCopyrightText: Copyright (c) 2022-2023 by Rivos Inc.
# SPDX-FileCopyrightText: Copyright (c) 2003-2022 Eelco Dolstra and the Nixpkgs/NixOS contributors
# Licensed under the MIT License, see LICENSE for details.
# SPDX-License-Identifier: MIT
{
  description = "qemu";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nix-filter.url = "github:numtide/nix-filter";
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    nix-filter,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        flake-parts.flakeModules.easyOverlay
      ];
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      perSystem = {
        final,
        lib,
        ...
      }: rec {
        packages = rec {
          qemu = let
            qemuVersion = lib.fileContents ./VERSION;
            version = "${qemuVersion}-g${self.shortRev or "dirty"}";
            src = nix-filter.lib {
              root = ./.;
              exclude = [
                ./flake.lock
                ./flake.nix
                ./rivos
              ];
            };
          in
            final.callPackage ./rivos/nix {
              inherit src version;
            };
          default = qemu;
        };
        overlayAttrs = packages;
      };
    };
}
