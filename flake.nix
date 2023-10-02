{
  description = "A very basic flake";

  outputs = { self, nixpkgs }: {

    devShells.x86_64-linux.default = import ./shell.nix {
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    };
    devShells.x86_64-linux.embedded-like = with nixpkgs.legacyPackages.x86_64-linux;
      /* CC=gcc CXX=g++ BUILD_DIR_NAME="build" cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -S . -B ./$BUILD_DIR_NAME -G "Ninja" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$PWD/$BUILD_DIR_NAME/install"
        -DENABLE_PRESENCE=ON
        -DENABLE_REDIS=OFF
        -DENABLE_SNMP=OFF
        -DENABLE_SOCI=ON
        -DENABLE_TRANSCODER=ON
        -DENABLE_MDNS=OFF
        -DENABLE_EXTERNAL_AUTH_PLUGIN=OFF
        -DENABLE_JWE_AUTH_PLUGIN=OFF
        -DINTERNAL_LIBSRTP2=ON
        -DINTERNAL_JSONCPP=OFF
        -DENABLE_CONFERENCE=OFF
        -DENABLE_SOCI_POSTGRESQL_BACKEND=OFF
        -DENABLE_B2BUA=OFF
        -DENABLE_UNIT_TESTS=OFF
        -DENABLE_STRICT_LINPHONESDK=OFF
      */
      mkShell
        {
          buildInputs =
            [
              cmake
              git
              openssl
              python3
              perl
              xercesc
              nghttp2
              protobuf
              sqlite
              speex
              libmysqlclient
              msgpack
              ninja # Optional. You can use "Unix makefiles" instead
            ];
        };

    packages.x86_64-linux.hello = nixpkgs.legacyPackages.x86_64-linux.hello;

    defaultPackage.x86_64-linux = self.packages.x86_64-linux.hello;

  };
}
