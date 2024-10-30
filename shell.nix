args@{ pkgs ? import <nixpkgs> { }, nghttp2 ? pkgs.nghttp2, ... }:

import ./nix/base.nix ({
  inherit pkgs nghttp2;
  enableUnitTests = true;
  enableB2bua = true;
  enableOpenId = true;
  additionalInputs = ps: with ps; [
    nixpkgs-fmt
    ccache
    gdb
  ] ++ (with llvmPackages_19; [
    clang-tools # clangd, clang-format (⚠️ MUST come before clang to set precedence in PATH for clangd... otherwise it fails to find std headers)
    clang # We currently only generate coverage data with clang (you have to change your `CC` env var)
    libllvm # Adds llvm-symbolizer which adds line numbers to AddressSanitizer traces when compiling with clang
  ]);
} // args)
