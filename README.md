# CBC-CTS and OFB + CMAC

AES CBC with CTS and OFB with CMAC encryption algorithms for my CS studies

Generates a 8 byte hex key on encryption of uses a specified key

Sample plaintext `message.txt` provided

## Commands

Pass as arguments:

- `e` - for encryption or `d` - for decryption
- file to encrypt/decrypt
- `cbc` - for CBC-CTS or `OFB` - for OFB + CMAC
- file with hex key for decryption

### CBC

```sh
python md1.py e message.txt cbc
python md1.py d output_encrypted cbc key_hex
```

### OFB

```sh
python md1.py e message.txt OFB
python md1.py d output_encrypted OFB key_hex
```

## Credits

CMAC generation modified from
https://github.com/SecureAuthCorp/impacket/blob/master/impacket/crypto.py#L94
Original author: Alberto Solino (beto@coresecurity.com)
