import pymem, pymem.process
import re
import struct

def pattern_to_regex(pattern: str) -> str:
    regex = b""
    for byte in pattern.split():
        if byte == "?":
            regex += b"."
        else:
            regex += re.escape(bytes.fromhex(byte))
    return regex

def scan_pattern(pm, module, pattern: str) -> int:
    module_address = pymem.process.module_from_name(pm.process_handle, module).lpBaseOfDll
    module_size = pymem.process.module_from_name(pm.process_handle, module).SizeOfImage
    bytes_read = pm.read_bytes(module_address, module_size)
    
    regex = re.compile(pattern_to_regex(pattern), re.DOTALL)
    match = regex.search(bytes_read)
    if not match:
        raise Exception("Pattern not found.")
    
    return module_address + match.start()

def patch_bytes(pm, address: int, patch_data: bytes):
    return pm.write_bytes(address, patch_data, len(patch_data))

def main() -> None:
    pm = pymem.Pymem("Growtopia.exe")

    sigma = "F3 0F 10 0D ? ? ? ? E8 ? ? ? ? 48 8B 4D"
    try:
        address = scan_pattern(pm, "Growtopia.exe", sigma) + 4
        print(f"Pattern found at: {hex(address)}")
        patch_bytes(pm, address, bytes([0xE3, 0xB0, 0x20, 0x00]))
        print("Patched!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
