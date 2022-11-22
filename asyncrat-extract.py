#####################################################
#                              #                    #
#  AsyncRAT Config Extractor   #  Author: KrknSec   #
#                              #                    #
#########################################################################
#                                                                       #
#  Description: Uses dnlib to parse the binary. Then                    #
#                it tries two different extractors. Extractor           #
#                one is the default AsyncRAT extractor. Extractor       #
#                two is an extractor for a variant observed.            #
#                                                                       #
#########################################################################
#                                                                       #
#  Usage: python asyncrat-extract.py <path to sample>                   #
#                                                                       #
#########################################################################

# Get the imports and things needed for .NET python interaction
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import json
import sys
import pefile
import sys, struct, clr
clr.AddReference("C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App\\7.0.0\\System.Memory") # Ensure the full path to the System.Memory DLL is included. I don't believe this is necessary on Linux/Mac with Mono [You don't have to append .dll to the end]
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type

DNLIB_PATH = 'C:\\Users\\KrknSec\\Desktop\\AsyncRAT-Config-Extractor\\dnlib' # Input the full path to your dnlib.dll. It won't work with simply "./dnlib" [You don't have to append .dll to the end]
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

# Time to start getting the .NET things
def get_salt():
    return bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")

# Extractor for a variant observed
def extractor2():
    # Get the sample data
    TARGET_PATH = sys.argv[1]
    file_data = open(TARGET_PATH, "rb").read()
    module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

    arr_strings = []
    counter = 0
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody: 
                continue
            if not method.Body.HasInstructions: 
                continue
            if not method.IsConstructor:
                continue
            if len(method.Body.Instructions) < 20:
                continue
            key_set = False 
            block_set = False
            for ptr in range(30):
                if 'ldstr' in method.Body.Instructions[ptr].ToString():
                    arr_inst = method.Body.Instructions[ptr]
                    arr_strings.append(arr_inst.Operand)    
                    #print(arr_strings)
    hosts = arr_strings[5].replace("https://", "")
    port = arr_strings[0].replace("https://", "")
    config = {}
    config = {
        "family": "asyncrat",
        "hosts": hosts[::-1],
        "port": port[::-1],
    }
    print("\n[+] Config \n-------------")
    print(json.dumps(config, indent=2))


# Extractor for the normal AsyncRAT
def extractor():
    # Get the sample data
    TARGET_PATH = sys.argv[1]
    file_data = open(TARGET_PATH, "rb").read()
    module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

    arr_strings = []
    counter = 0
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody: 
                continue
            if not method.Body.HasInstructions: 
                continue
            if not method.IsConstructor:
                continue
            if len(method.Body.Instructions) < 20:
                continue
            key_set = False 
            block_set = False
            for ptr in range(30):
                if 'ldstr' in method.Body.Instructions[ptr].ToString():
                    arr_inst = method.Body.Instructions[ptr]
                    arr_strings.append(arr_inst.Operand)    
                    #print(arr_strings)
    key = arr_strings[6]
    bytes64 = base64.b64decode(key)
    config = {}
    config = {
        "family": "asyncrat",
        "hosts": decrypt(bytes64, base64.b64decode(arr_strings[1])),
        "port": decrypt(bytes64, base64.b64decode(arr_strings[0])),
        "version": decrypt(bytes64, base64.b64decode(arr_strings[2])),
        "install": decrypt(bytes64, base64.b64decode(arr_strings[3])),
        "install_folder": arr_strings[4],
        "anti": decrypt(bytes64, base64.b64decode(arr_strings[11])),
        "mutex": decrypt(bytes64, base64.b64decode(arr_strings[7]))
    }
    print("\n[+] Config \n-------------")
    print(json.dumps(config, indent=2))

def decrypt(key, ciphertext):
    aes_key = PBKDF2(key, get_salt(), 32, 50000)
    cipher = AES.new(aes_key, AES.MODE_CBC, ciphertext[32 : 32 + 16])
    plaintext = cipher.decrypt(ciphertext[48:]).decode("ascii", "ignore").strip()
    return plaintext

def getResults():
    results = []
    

if __name__ == "__main__":
    try:
        extractor()
    except:
        print("[-] Error! Could be an older version or a variant!")
        print("[!] Trying a different method of extraction...")
        try:
            extractor2()
        except:
            print("[-] Other form of extraction didn't work! Manual analysis required!")
