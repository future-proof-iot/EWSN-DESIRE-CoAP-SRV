desire_coap_server
==
A python coap server for offloading RTL, ETL (for debug) and Exposure Status Request (ESR).

Enrollment is done by declaring the list of nodes uuids on sever start as args.

Example of a server with nodes DW01E2 and DW0AB34 enrolled (Two default test
nodes UIDs are always enrolled DW0001 and DW0002)

```shell
$ python desire_coap_srv.py --node-uid DW01E2 DW0AB34
```

For each node, identified by a 16-bit uid in hex format, the following resources are exposes:

| Resource URI                      | Semantic                                                                                                                                           |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| `coap://localhost/<uid>/ertl`     | [POST, GET] a json/cbor(tag=51966) object representing the epoch's RTL and ETL data                                                                |
| `coap://localhost/<uid>/infected` | [POST, GET] a json/cbor(tag=51962) object representing node's infection (a boolean)                                                                     |
| `coap://localhost/<uid>/esr`      | [GET] return an json/cbor(tag=51967) object integer equal to true if the node `<uid>`<br>was exposed to an infected user, and false otherwise      |

*Example of aiocoap-client session with the server:*
- POST ERTL data [static/ertl.json](static/ertl.json) for node `DW0456`
```shell
$ aiocoap-client -q coap://localhost/DW0456/ertl -m POST --content-format application/json --payload @static/ertl.json
```
- POST ERTL data [static/ertl.cbor](static/ertl.cbor) for node `DW0456`
```shell
$ aiocoap-client -q coap://localhost/DW0456/ertl -m POST --content-format application/cbor --payload @static/ertl.cbor
```
- GET ERTL data in `json` format for node `DW0456`
```shell
$ aiocoap-client -q coap://localhost/DW0456/ertl --content-format application/json
{
    "epoch": 332,
    "pets": [
        {
            "pet": {
                "etl": "vwqMHjrpYru3s3BhZJqNpdv7yVTcukv9j22PNHEzSkI=",
                "rtl": "UFGTQCsxu3f7l2QsKwpnimSW1vfuBBp3C2C8rdAmg14=",
                "exposure": 780,
                "req_count": 432,
                "avg_d_cm": 151
            }
        },
        {
            "pet": {
                "etl": "2IDGdmnLl2JDBRxfjVsC5MMqMdA1lGjlqzUjnlmS9Ew=",
                "rtl": "EDfFx+xAXrsAaIJaNbUgdVFf0WTktZIiyJwzhF7dqBQ=",
                "exposure": 640,
                "req_count": 323,
                "avg_d_cm": 71
            }
        }
    ]
}
```
- GET ERTL data in `cbor` format for node `DW0456`
```shell
$ aiocoap-client -q coap://localhost/DW0456/ertl --content-format application/cbor
CBORTag(51966, [332, [[b'\xbf\n\x8c\x1e:\xe9b\xbb\xb7\xb3pad\x9a\x8d\xa5\xdb\xfb\xc9T\xdc\xbaK\xfd\x8fm\x8f4q3JB', b'PQ\x93@+1\xbbw\xfb\x97d,+\ng\x8ad\x96\xd6\xf7\xee\x04\x1aw\x0b`\xbc\xad\xd0&\x83^', 780, 432, 151], [b'\xd8\x80\xc6vi\xcb\x97bC\x05\x1c_\x8d[\x02\xe4\xc3*1\xd05\x94h\xe5\xab5#\x9eY\x92\xf4L', b'\x107\xc5\xc7\xec@^\xbb\x00h\x82Z5\xb5 uQ_\xd1d\xe4\xb5\x92"\xc8\x9c3\x84^\xdd\xa8\x14', 640, 323, 71]]])
```

- GET infected data in `json` format for node `DW0456` - allows him to recover
the infection status
```shell
$ aiocoap-client -q coap://localhost/DW0456/infected --content-format application/json
{"infected": false}
```

- GET infected data in `cbor` format for node `DW0456` - allows him to recover the infection status
```shell
$ aiocoap-client -q coap://localhost/DW0456/infected --content-format application/cbor
CBORTag(51962, [False])
```

- POST infected data in `json` format for node `DW0456` - allows him to declare an infection
```shell
$ aiocoap-client -q coap://localhost/DW0456/infected -m POST --content-format application/json --payload @static/infected.json
```

- POST infected data in `cbor` format for node `DW0456` - allows him to declare an infection
```shell
$ aiocoap-client -q coap://localhost/DW0456/infected -m POST --content-format application/cbor --payload @static/infected.cbor
```

- GET exposure data in `json` for node `DW0456` - allows him to check if he was in contact with another infected user
```shell
$ aiocoap-client -q coap://localhost/DW0456/esr --content-format application/json
{
    "contact": false
}
```

- GET exposure data in `cbor` for node `DW0456` - allows him to check if he was in contact with another infected user
```shell
$ aiocoap-client -q coap://localhost/DW0456/esr --content-format application/cbor
CBORTag(51967, [False])
```

*Note on CBOR files in [./static](./static) folder*
The payloads have binary cbor files that can be dumped using this helper [tools/dump_cbor_file.py](tools/dump_cbor_file.py) as follows, where the hex bytes are printed then decoded using the system utility
```shell
$ python tools/dump_cbor_file.py static/ertl.cbor
line [len = 162 bytes] = d9cafe8219014c82855820bf0a8c1e3ae962bbb7b37061649a8da5dbfbc954dcba4bfd8f6d8f3471334a425820505193402b31bb77fb97642c2b0a678a6496d6f7ee041a770b60bcadd026835e19030c1901b01897855820d880c67669cb976243051c5f8d5b02e4c32a31d0359468e5ab35239e5992f44c58201037c5c7ec405ebb0068825a35b52075515fd164e4b59222c89c33845edda8141902801901431847
CBOR decoding:
{
    "CBORTag:51966": [
        332,
        [
            [
                "\\xbf\n\\x8c\u001e:\\xe9b\\xbb\\xb7\\xb3pad\\x9a\\x8d\\xa5\\xdb\\xfb\\xc9TܺK\\xfd\\x8fm\\x8f4q3JB",
                "PQ\\x93@+1\\xbbw\\xfb\\x97d,+\ng\\x8ad\\x96\\xd6\\xf7\\xee\u0004\u001aw\u000b`\\xbc\\xad\\xd0&\\x83^",
                780,
                432,
                151
            ],
            [
                "؀\\xc6vi˗bC\u0005\u001c_\\x8d[\u0002\\xe4\\xc3*1\\xd05\\x94h\\xe5\\xab5#\\x9eY\\x92\\xf4L",
                "\u00107\\xc5\\xc7\\xec@^\\xbb\u0000h\\x82Z5\\xb5 uQ_\\xd1d䵒\"Ȝ3\\x84^ݨ\u0014",
                640,
                323,
                71
            ]
        ]
    ]
}
```
Note that the hex string can also be deconded online on [http://cbor.me/](http://cbor.me/).

*Note on CBOR packet length*
In order to estimate the CBOR packet length for the ERTL payload (ErtlPayload class), one can generate a random object and serialize to cbor. Example running [tools/print_cbor_size.py](tools/print_cbor_size.py) with two random pets
```shell
$ PYTHONPATH=$PWD python tools/print_cbor_size.py 2
CBOR packet size for 2 pets
EncounterData to array = [b'\x97-\x8f^\xaf\xd2\xf5\xeb\n\x1c\x95\x06^#vrCw2\x00\xfaDO\xd7\x1c\x04\xe7u\x90\xe4Et', b'e61\xeal\x84\xef\x8e\xb1\x0f\x85\xbe\xda\xd0\xdcWZC%b\xa0?\xff\xf4\x08,\x04\x96e\xf3G\xb6', 67, 56, 72.533]
EncounterData to array = [b'R\t\x07\xa9\xad\xcc\xb0\xf9\xb4\xcf\x84U\x87\x95la\xf6\xd6\x0bA\x19\x83\x07\x9b\xe5\xdd\xe5<\x8c\xf7\xa1q', b'g\x7f\xd8\xa4\xb6\xb2\r\xed]\xf1ic\x19\x89r\x062\xc5-~\x9d\xbe\xb3\xbd\x12\x10\xa6\x16\xa5\x91\xc8\xe3', 15, 97, 10.599]
ErtlPayload(epoch=10, pets=[PetElement(pet=EncounterData(etl=b'\x97-\x8f^\xaf\xd2\xf5\xeb\n\x1c\x95\x06^#vrCw2\x00\xfaDO\xd7\x1c\x04\xe7u\x90\xe4Et', rtl=b'e61\xeal\x84\xef\x8e\xb1\x0f\x85\xbe\xda\xd0\xdcWZC%b\xa0?\xff\xf4\x08,\x04\x96e\xf3G\xb6', exposure=67, req_count=56, avg_d_cm=72.533)), PetElement(pet=EncounterData(etl=b'R\t\x07\xa9\xad\xcc\xb0\xf9\xb4\xcf\x84U\x87\x95la\xf6\xd6\x0bA\x19\x83\x07\x9b\xe5\xdd\xe5<\x8c\xf7\xa1q', rtl=b'g\x7f\xd8\xa4\xb6\xb2\r\xed]\xf1ic\x19\x89r\x062\xc5-~\x9d\xbe\xb3\xbd\x12\x10\xa6\x16\xa5\x91\xc8\xe3', exposure=15, req_count=97, avg_d_cm=10.599))])
{"epoch": 10, "pets": [{"pet": {"etl": "ly2PXq/S9esKHJUGXiN2ckN3MgD6RE/XHATndZDkRXQ=", "rtl": "ZTYx6myE746xD4W+2tDcV1pDJWKgP//0CCwElmXzR7Y=", "exposure": 67, "req_count": 56, "avg_d_cm": 72.533}}, {"pet": {"etl": "UgkHqa3MsPm0z4RVh5VsYfbWC0EZgweb5d3lPIz3oXE=", "rtl": "Z3/YpLayDe1d8WljGYlyBjLFLX6dvrO9EhCmFqWRyOM=", "exposure": 15, "req_count": 97, "avg_d_cm": 10.599}}]}
cbor packet length = 169
D9CAFE820A82855820972D8F5EAFD2F5EB0A1C95065E23767243773200FA444FD71C04E77590E445745820653631EA6C84EF8EB10F85BEDAD0DC575A432562A03FFFF4082C049665F347B618431838FB4052221CAC083127855820520907A9ADCCB0F9B4CF845587956C61F6D60B411983079BE5DDE53C8CF7A1715820677FD8A4B6B20DED5DF169631989720632C52D7E9DBEB3BD1210A616A591C8E30F1861FB402532B020C49BA6
```

## EDHOC support

The coap_server has been extended with [EDHOC](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/)
support, when starting the server a `</.well-known/edhoc>,` resources is exposed
acting as the `responder` in and EDHOC exchange. Enrolled devices will then be
able to perform an EDHOC key-exchange with the server, once a key exchange is
successfully performed the server will derive a security context (CryptoCtx python
module) to encrypt all future transactions with the device.

Currently support is only CipherSuite0 with SIGN_SIGN method. So AES-CCM is
used for encryption.

### Modified Enrollment

For an EDHOC key exchange to succeed the server must know the devices credentials
and the devices must know the servers credentials. To easily fetch the credentials
credentials are registered with and ID matching the identifier used for enrollment.

Helper scripts are provided to generate and export:

* Server credentials

    generate server side keys (call only once or update keys on client side every time
    keys are updated.

    ```python
    python tools/edhoc_generate_keys.py
    ```

    export the server credentials to a c formatted array:

    ```python
    python tools/edhoc_keys_header.py --out-dir <some-dir>
    ```

    The server KID (key id) will always be `PEPPER`

* Device credentials:

    The script takes as an input a base64 encode id and outputs a c file holding
    all the required credentials. If for example the device ID was `DW1234` then
    on a unix system one can do:

    ```python
    echo "DW1234" | base64 | xargs python tools/edhoc_keys_header.py --out-dir <some-dir> --kid
    ```

Both generate c files (`DW****_keys.c` and `PEPPER_keys.c`) will contain all the
boiler plate code to be directly included by the matching `edhoc_coap` c module.

The server will be willing to server nodes over an unsecure channel (no EDHOC
key exchange, no encryption), but if a security context is derived once the all
future exchanges will be encrypted. A security context can be reset from the client
side by performing a new EDHOC key exchange.

### Automatic Test

A pytest based test infrastructure is provided, to run install the requirements:

$ pip install -r test_requirements.txt

Then simply run by calling:

$ pytest

Test servers are spawn for some of the tests, these will turn on 5683 PORT by
default (although this can be parameterized), so check that no other process
is turning on that PORT.
