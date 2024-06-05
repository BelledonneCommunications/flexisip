{ pkgs
, enableUnitTests
, enableB2bua
, enableOpenId
}:

let
  # https://github.com/NixOS/nixpkgs/blob/7adc9c14ec74b27358a8df9b973087e351425a79/pkgs/development/libraries/nghttp2/default.nix#L8
  nghttp2 = pkgs.nghttp2.override { enableAsioLib = enableUnitTests; };
  python = pkgs.python3.withPackages (ps: with ps; [ pystache six ]);
  inherit (pkgs.lib) optional optionals;
in

with pkgs;

[
  # Bare minimum to build with `nix-shell --pure` with the default config
  cmake
  git
  openssl
  postgresql
  jansson
  zlib
  python
  perl
  sqlite
  srtp
  speex
  xercesc
  libxml2
  doxygen
  nghttp2
  net-snmp
  hiredis
  protobuf
  libmysqlclient
  yasm
  ninja # Optional. You can use "Unix makefiles" instead
]
++ optionals enableUnitTests [
  boost
  redis
  mariadb
]
++ optionals enableB2bua [
  jsoncpp
]
++ optionals (enableB2bua && enableUnitTests) [
  libvpx # We need a video codec for video calls to establish successfully
]
++ optionals enableOpenId [
  cpp-jwt
  nlohmann_json
]
