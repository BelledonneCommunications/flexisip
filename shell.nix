args@{ ... }:

import ./nix/base.nix ({
  pkgs = import <nixpkgs> { };
  enableUnitTests = true;
  enableB2bua = true;
  additionalInputs = ps: with ps; [
    nixpkgs-fmt
    ccache
    clang
  ];
} // args)
