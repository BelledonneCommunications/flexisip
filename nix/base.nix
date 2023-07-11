let
  pinned_nixpkgs = builtins.fetchTarball {
    # Descriptive name to make the store path easier to identify
    name = "nixos-stable-2021-11-30";
    # Commit hash for tag 21.11
    url =
      "https://github.com/nixos/nixpkgs/archive/a7ecde854aee5c4c7cd6177f54a99d2c1ff28a31.tar.gz";
    # Hash obtained using `nix-prefetch-url --unpack <url>`
    sha256 = "162dywda2dvfj1248afxc45kcrg83appjd0nmdb541hl7rnncf02";
  };
in

{ pkgs ? import pinned_nixpkgs { }
, additionalInputs ? (_: [ ])
, enableUnitTests ? false
, enableB2bua ? false
, ...
}:

let
  dependencies = import ./dependencies.nix { inherit pkgs enableUnitTests enableB2bua; };
in

pkgs.mkShell.override { stdenv = pkgs.gcc13Stdenv; } {
  buildInputs = dependencies
    ++ additionalInputs pkgs;
}
