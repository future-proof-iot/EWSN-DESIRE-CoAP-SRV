from binascii import hexlify
import sys

from desire_srv.coap.desire.payloads import ErtlPayload


if __name__ == "__main__":
    assert len(sys.argv) > 1, print("number of pets must pe passed as argument")
    num_pets = int(sys.argv[1], 10)

    print(f"CBOR packet size for {num_pets} pets")

    ertl = ErtlPayload.rand(num_pets)
    ert_cbor_bytes = ertl.to_cbor_bytes()

    print(ertl)
    print(ertl.to_json_str())
    print(
        "cbor packet length = "
        f"{len(ert_cbor_bytes)}\n{hexlify(ert_cbor_bytes).decode().upper()}"
    )
