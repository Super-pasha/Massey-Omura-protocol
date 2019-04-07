# Massey-Omura protocol

### Basic information

This script implements a client-server application for transfering files over a secure channel. To save benefits of both symmetric and asymmetric encryption, file encryption (decryption) is performed with 3DES algorithm and Massey-Omura protocol is used to deliver client's 3DES key to server. 

![how it works](https://github.com/Super-pasha/Massey-Omura-protocol/blob/master/Doc/scheme.svg)

### Requirements

- python3
- [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [asn1](https://pypi.org/project/asn1/)

### Usage

Launch server using command:
```shell=
python3 main.py server localhost 9000
```

Then launch client:
```shell=
python3 main.py client localhost 9000 test.jpg
```

If no errors occured, you will see *test.srv.jpg* file received by server in current folder. 

### Contents

| File name      | Description                                   |
| -------------- | --------------------------------------------- |
| main.py        | Client and server implementation              |
| arithmetic.py  | Modular arithmetic operations                 |
| MillerRabin.py | Miller-Rabin algorithm for generating primes  |
| cryptutils.py  | Cryptographic protocol implementation         |
| asnapi.py      | Functions for storing messages in asn1 format |
