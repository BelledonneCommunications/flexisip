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
  # https://github.com/NixOS/nixpkgs/blob/7adc9c14ec74b27358a8df9b973087e351425a79/pkgs/development/libraries/nghttp2/default.nix#L8
  nghttp2 = pkgs.nghttp2.override { enableAsioLib = enableUnitTests; };
  python = pkgs.python3.withPackages (ps: with ps; [ pystache six ]);
  inherit (pkgs.lib) optional optionals;
in

with pkgs;

mkShell {
  buildInputs = [
    cmake
    git
    ninja
    redis
    openssl
    postgresql
    jansson
    zlib
    sqlite
    srtp
    speex
    xercesc
    libxml2
    python
    doxygen
    nghttp2
    net-snmp
    hiredis
    protobuf
    libmysqlclient
    mbedtls
  ]
  ++ additionalInputs pkgs
  ++ optional enableUnitTests boost
  ++ optionals enableB2bua [ffmpeg libv4l xorg.libX11 glew];
}
