{
  description = "Flexisip development environments";

  inputs = {
    nixpkgs-with-nghttp2-asio.url = github:NixOS/nixpkgs/a565059a348422af5af9026b5174dc5c0dcefdae;
  };

  outputs = { self, nixpkgs, nixpkgs-with-nghttp2-asio }: {

    devShells.x86_64-linux.default = import ./shell.nix {
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      # https://github.com/NixOS/nixpkgs/blob/7adc9c14ec74b27358a8df9b973087e351425a79/pkgs/development/libraries/nghttp2/default.nix#L8
      nghttp2 = nixpkgs-with-nghttp2-asio.legacyPackages.x86_64-linux.nghttp2.override { enableAsioLib = true; };
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
        -DINTERNAL_LIBSRTP2=ON
        -DINTERNAL_JSONCPP=OFF
        -DENABLE_CONFERENCE=OFF
        -DENABLE_SOCI_POSTGRESQL_BACKEND=OFF
        -DENABLE_B2BUA=OFF
        -DENABLE_VOICEMAIL=OFF
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
              sqlite
              speex
              libmysqlclient
              ninja # Optional. You can use "Unix makefiles" instead
            ];
        };

    packages.x86_64-linux.hello = nixpkgs.legacyPackages.x86_64-linux.hello;

    defaultPackage.x86_64-linux = self.packages.x86_64-linux.hello;

  };
}
