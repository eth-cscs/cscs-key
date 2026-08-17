{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "cscs-key";
  version = "1.1.0"; # keep in sync with Cargo.toml

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "Manage CSCS SSH-key certificates";
    homepage = "https://github.com/eth-cscs/cscs-key";
    license = lib.licenses.bsd3;
    mainProgram = "cscs-key";
  };
}
