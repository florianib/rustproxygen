# RustProxyGen
This project creates a (forwarder) proxy dll rust template.

# Build 
```
cargo build --release
```

# Usage
```
Usage: rustproxygen.exe [OPTIONS] --dll <DLL>

Options:
  -d, --dll <Dll Path>
  -s, --shellcode <Shellcode Path>
  -o, --output <Output Directory>
  -r, --resources <Resources Directory>
  -e, --encryption <AES>
  -h, --help                     Print help
  -V, --version                  Print version
```


# Example

## DLL Proxy with Shellcode Injection
```
rustproxygen.exe -o C:\temp\output -s C:\temp\shellcode.bin -d C:\temp\test.dll -r C:\temp\resources -e AES
	Proxying "C:\\temp\\test.dll"
	Embedding shellcode "C:\\temp\\shellcode.bin"
	Parsed an x64 PE file
	Found 2 exported functions
	Using AES encryption
	Wrote shellcode to "C:\\temp\\output\\shellcode.rs"
	Wrote proxy dll template to "C:\\temp\\output\\proxy.rs"
```

## Shellcode-Only Encryption (No DLL)
When no DLL is provided, the tool encrypts the shellcode and generates only the encryption artifacts:

```
rustproxygen.exe -o C:\temp\output -s C:\temp\shellcode.bin -e AES
	Embedding shellcode "C:\\temp\\shellcode.bin"
	No DLL specified - encrypting shellcode only
	Using AES encryption
	Wrote shellcode.rs to "C:\\temp\\output\\shellcode.rs"
	Wrote decryption.rs to "C:\\temp\\output\\decryption.rs"
	Shellcode encryption complete!
```

**Output Files:**
- `shellcode.rs` - Contains the encrypted shellcode as a static byte array
- `decryption.rs` - Contains the hardcoded AES-256-GCM key, nonce, and `decrypt_shellcode()` function

**Note:** The `--encryption` flag is **required** when no DLL is provided. Omitting it will result in an error.
