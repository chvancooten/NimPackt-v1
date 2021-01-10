    #[ 
        NimPackt-Template-ExecuteAssembly.nim starts here
    ]#
    var assembly = load(decoded)

    # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let arr = toCLRVariant(["argument1", "argument2"], VT_BSTR)
    #[ PLACEHOLDERARGUMENTS ]#

    assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))