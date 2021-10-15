from binascii import hexlify
import sys
import os

if __name__ == "__main__":
    assert len(sys.argv)>1, print("CBOR binary file must be passed as argument")
    with open(sys.argv[1],'rb') as f:
        line = b''.join(f.readlines())
        hex_line = hexlify(line).decode()
        print(f'line [len = {len(line)} bytes] = {hex_line}')
        cmd = f'echo {hex_line} | xxd -r -ps  | python -m cbor2.tool --pretty '
        print("CBOR decoding:")
        os.system(cmd)