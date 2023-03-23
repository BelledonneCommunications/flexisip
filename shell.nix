args@{ pkgs ? import <nixpkgs> { }, ... }:

import ./nix/base.nix ({
  inherit pkgs;
  enableUnitTests = true;
  enableB2bua = true;
  additionalInputs = ps: with ps; [
    nixpkgs-fmt
    ccache
    clang-tools_13 # clangd, clang-format
    llvmPackages_13.libllvm # Adds llvm-symbolizer which adds line numbers to AddressSanitizer traces when compiling with clang
    gdb
  ];
} // args)
