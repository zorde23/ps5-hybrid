# ps5-hybrid

Runs PS5 executables natively on Windows by joining two projects:

- [AnyPS5](https://github.com/boykopovar/AnyPS5): the relinker that converts the executable to a native Windows program, the kernel and the system libraries.
- [kyty-gpu-hybrid](https://github.com/zorde23/kyty-gpu-hybrid) (submodule `3rdparty/kyty-gpu`): Kyty's GPU (command processor, shader recompiler, Vulkan renderer) built as `kyty_gpu.dll` and used as the graphics backend.

No emulation of the CPU and no separate runtime process. This repository is the generic base: it holds nothing specific to any title. A project for one title is a fork of it that adds its own profile in `tools/hybrid-profiles/`.

## What this base adds to AnyPS5

- `tools/build_hybrid.ps1`: one script that builds the relinker, the libraries and `kyty_gpu.dll`, and with `-Eboot`/`-GameDir` lays out a folder ready to run.
- Profiles (`tools/hybrid-profiles/base.ini`): the relinker flags and the runtime keys, written to `ps5-hybrid.ini` beside the executable so a double-click launch gets the same settings as a script.
- Red-zone guard for the host libraries (relinker flags and per-frame tables).
- `APS5_NET_LOCAL_ONLY=1`: the title's sockets stay on the loopback interface, so Windows never asks for network access.
- Kernel fixes taken from AnyPS5 upstream by cherry-pick (semaphores, event flags).

## Build and run

```powershell
git clone --recursive https://github.com/zorde23/ps5-hybrid
powershell -ExecutionPolicy Bypass -File tools\build_hybrid.ps1
powershell -ExecutionPolicy Bypass -File tools\build_hybrid.ps1 -Eboot C:\dump\eboot.bin -GameDir C:\dump -Output C:\hybrid
```

Requirements, every option and the folder layout: [Usage, "Kyty GPU hybrid build"](docs/user/USAGE.md#kyty-gpu-hybrid-build). The script lists anything missing and stops before building. Tested on Windows 11 with an AMD Radeon RX 6750 XT.

The game's files never go into the repository: `-GameDir` links them into `app0\` and never copies, moves or deletes them.

## Branches

- `main`: the base, tested end to end (build, unit tests, menu smoke run, frame-capture replay) before each push.
- Upstream AnyPS5 changes come in by cherry-pick after review, not by merge.

## More

[Build instructions](docs/dev/BUILD.md), [Architecture](docs/dev/ARCHITECTURE.md), [Environment variables](docs/dev/ENVIRONMENT.md), [Conventions](docs/dev/CONVENTIONS.md), [Contributing](CONTRIBUTING.md)

## Credits

- boykopovar and the AnyPS5 contributors.
- InoriRus for Kyty, and TheCruZ and the KytyPS5 contributors.

## Disclaimer

This project is intended for interoperability, research, preservation, and compatibility purposes. It does not include, distribute, or require copyrighted software, firmware, cryptographic keys, or proprietary libraries. Users are responsible for ensuring that any binaries used with this project are obtained and used in accordance with applicable laws and their respective license terms.

It is not affiliated with, authorized or endorsed by Sony Interactive Entertainment. "PlayStation" and "PS5" are trademarks of Sony Interactive Entertainment Inc.

## License

GNU General Public License version 2 only, as AnyPS5. The Kyty submodule is GPL-2.0 with original Kyty code under MIT (see its `LICENSES`).
