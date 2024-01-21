{ pkgs }: {
  deps = [
    pkgs.sqlite.bin
    pkgs.rustc
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
  ];
  env = {
    PYTHON_LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.rustc
      pkgs.libxcrypt
    ];
  };
}