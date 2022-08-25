# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# SPDX-FileCopyrightText: Copyright (c) 2003-2022 Eelco Dolstra and the Nixpkgs/NixOS contributors
# Licensed under the MIT License, see LICENSE for details.
# SPDX-License-Identifier: MIT
{
  description = "qemu";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    # to work with older version of flakes
    lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

    # Generate a user-friendly version number.
    version = builtins.substring 0 8 lastModifiedDate;

    # System types to support.
    supportedSystems = [
      "x86_64-linux"
      "aarch64-linux"
      "riscv64-linux"
    ];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    # Nixpkgs instantiated for supported system types.
    nixpkgsFor = forAllSystems (system:
      import nixpkgs {
        inherit system;
        overlays = [self.overlays.default];
      });

    hostCpuTargets = [
      "aarch64-softmmu"
      "riscv32-softmmu"
      "riscv64-softmmu"
      "x86_64-softmmu"
      "aarch64-linux-user"
      "riscv64-linux-user"
      "x86_64-linux-user"
    ];
  in {
    overlays.default = final: prev: {
      qemu = final.callPackage ./rivos/nix {
        src = self;
        inherit hostCpuTargets version;
      };
    };

    # Provide some binary packages for selected system types.
    packages = forAllSystems (system: let
      qemu = (nixpkgsFor.${system}).qemu;
    in {
      inherit qemu;
      default = qemu;
    });

    # Tests run by 'nix flake check' and by Hydra.
    checks =
      forAllSystems
      (
        system: let
          qemu = nixpkgsFor.${system}.qemu.override {
            doCheck = true;
            # Ensure we didn't break other targets.
            hostCpuTargets = null;
          };
        in {
          # Only run qemu build + unittests now.
          inherit qemu;
        }
      );

    formatter = forAllSystems (system: nixpkgsFor.${system}.alejandra);
  };
}
