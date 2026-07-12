{
  description = "presto - user-mode NAT datapath for sandboxes";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "presto";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
        };

        # QUIC throughput tool (iperf-like, quicly based) used by the
        # bench_quic test.
        qperf = pkgs.stdenv.mkDerivation {
          pname = "qperf";
          version = "unstable-2024-06-20";
          src = pkgs.fetchFromGitHub {
            owner = "qubasa";
            repo = "qperf";
            rev = "423098cdc67f6b100b7413af1a876ef51722460d";
            hash = "sha256-Xlk5dpuq0+p7pPHijXDTPnxUK915DBOxgtDcES3tmbA=";
            fetchSubmodules = true;
          };
          nativeBuildInputs = with pkgs; [
            cmake
            pkg-config
            perl
          ];
          buildInputs = with pkgs; [
            openssl
            libev
          ];
          # Bundled quicly still uses pre-3.5 CMake syntax.
          env.CMAKE_POLICY_VERSION_MINIMUM = "3.5";
          installPhase = ''
            install -Dm755 qperf $out/bin/qperf
          '';
          meta.mainProgram = "qperf";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            # test harness
            iproute2
            util-linux
            # benchmark (tests/netns.rs bench, run with --ignored)
            iperf3
            passt
            # QUIC benchmark (tests/netns.rs bench_quic)
            self.packages.${pkgs.stdenv.hostPlatform.system}.qperf
            openssl
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
