# CBC-CTS and OFB + CMAC

AES CBC with CTS and OFB with CMAC encryption algorithms for my CS studies

Sample plaintext `message.txt` and key `key.hex` provided

## Commands

Pass as arguments:

- `e` - for encryption or `d` - for decryption
- file to encrypt/decrypt
- file with hex key
- `cbc` - for CBC-CTS or `OFB` - for OFB + CMAC

### CBC

```sh
python md1.py e message.txt key.hex cbc
python md1.py d output_encrypted key.hex cbc
```

### OFB

```sh
python md1.py e message.txt key.hex OFB
python md1.py d output_encrypted key.hex OFB
```

## Credits

CMAC generation modified from
https://github.com/SecureAuthCorp/impacket/blob/master/impacket/crypto.py#L94
Original author: Alberto Solino (beto@coresecurity.com)
