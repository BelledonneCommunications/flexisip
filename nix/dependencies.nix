{ pkgs
, enableUnitTests
, enableB2bua
, enableOpenId
, nghttp2 ? pkgs.nghttp2
}:

let
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
