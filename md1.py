import blowfish
import argparse
import secrets
from struct import pack, unpack

# Commands to encrypt and decrypt something
#
# CBC
# python md1.py e message.txt key.hex cbc
# python md1.py d output_encrypted key.hex cbc
#
# OFB
# python md1.py e message.txt key.hex OFB
# python md1.py d output_encrypted key.hex OFB

ENCRYPT = 'ENCRYPT'
DECRYPT = 'DECRYPT'
CBC = 'CBC'
OFB = 'OFB'
OUTPUT_ENCRYPTED = 'output_encrypted'
OUTPUT_DECRYPTED = 'output_decrypted'
BLOCK_SIZE = 8


def read_file(fileName):
    with open(fileName, 'r') as f:
        return ''.join(f.readlines())


def read_file_binary(fileName):
    with open(fileName, 'rb') as f:
        return bytes(0).join(f.readlines())


def write_file(data):
    with open(OUTPUT_DECRYPTED, 'w') as file:
        file.write(data)


def write_file_binary(data):
    with open(OUTPUT_ENCRYPTED, 'wb') as file:
        file.write(data)


def text_to_byte_array(plainText):
    byteArray = bytearray()
    byteArray.extend(map(ord, plainText))
    return byteArray


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def swap_blocks(blocks):
    length = len(blocks)
    blocks[length - 2], blocks[length - 1] = \
        blocks[length - 1], blocks[length - 2]
    return blocks


def encrypt_block_cbc(block, key, iv):
    cipher = blowfish.Cipher(key)

    # Pad block if size incorrect
    block_length = len(block)
    if block_length < BLOCK_SIZE:
        block += bytearray(BLOCK_SIZE - block_length)

    # XOR block with iv
    block = byte_xor(block, iv)

    cipher_block = cipher.encrypt_block(block)
    return cipher_block


def decrypt_block_cbc(block, key, iv):
    cipher = blowfish.Cipher(key)
    plain_block = cipher.decrypt_block(block)

    # XOR block with iv
    plain_block = byte_xor(plain_block, iv)

    return plain_block


def encrypt_cbc(plain_text, key):
    # Empty bytes for CBC
    iv = bytes(BLOCK_SIZE)

    text_length = len(plain_text)
    # Convert text to list of blocks
    plain_blocks = [plain_text[i:i+BLOCK_SIZE]
                    for i in range(0, text_length, BLOCK_SIZE)]
    cipher_blocks = []

    for block in plain_blocks:
        cipher_block = encrypt_block_cbc(block, key, iv)
        iv = cipher_block
        cipher_blocks.append(cipher_block)

    if text_length % 16 != 0:
        # Swap blocks
        cipher_blocks = swap_blocks(cipher_blocks)

    cypher_text = bytearray(0)
    for block in cipher_blocks:
        cypher_text += block

    # Truncate cypher text
    cypher_text = cypher_text[:text_length]

    return cypher_text


def decrypt_cbc(cipher_text, key):
    # Empty bytes for CBC
    iv = bytes(BLOCK_SIZE)

    cipher_length = len(cipher_text)
    # Convert text to list of blocks
    cipher_blocks = [cipher_text[i:i+BLOCK_SIZE]
                     for i in range(0, cipher_length, BLOCK_SIZE)]
    plain_blocks = []

    if cipher_length % 16 != 0:
        # Decrypt second-to-last block
        cipher = blowfish.Cipher(key)
        second_to_last = cipher.decrypt_block(cipher_blocks[-2])

        # Add missing bytes
        missing_bytes = second_to_last[-(BLOCK_SIZE - len(cipher_blocks[-1])):]
        cipher_blocks[-1] += missing_bytes

        # Swap blocks
        cipher_blocks = swap_blocks(cipher_blocks)

    for block in cipher_blocks:
        plain_block = decrypt_block_cbc(block, key, iv)
        iv = block
        plain_blocks.append(plain_block)

    plain_text = bytearray(0)
    for block in plain_blocks:
        plain_text += block

    # Truncate plain text
    plain_text = plain_text[:cipher_length]

    return plain_text


# Modified from
# https://github.com/SecureAuthCorp/impacket/blob/master/impacket/crypto.py#L94
# Original author: Alberto Solino (beto@coresecurity.com)
def gen_cmac(k, m, length):
    const_Zero = bytearray(BLOCK_SIZE)

    m = bytearray(m)
    K1, K2 = generate_subkey(k)
    n = len(m)//BLOCK_SIZE

    # If message one block long
    if n == 0:
        n = 1
        flag = False
    else:
        # Check is message a multiple of block size
        if (length % BLOCK_SIZE) == 0:
            flag = True
        else:
            n += 1
            flag = False

    M_n = m[(n-1)*BLOCK_SIZE:]
    if flag is True:
        M_last = xor_128(M_n, K1)
    else:
        # Pad last block
        M_last = xor_128(pad(M_n), K2)

    X = const_Zero
    for i in range(n-1):
        M_i = m[(i)*BLOCK_SIZE:][:BLOCK_SIZE]
        Y = xor_128(X, M_i)
        X = bytearray(encrypt_block(bytes(Y), k))
    Y = xor_128(M_last, X)
    T = encrypt_block(bytes(Y), k)

    return T


def generate_subkey(k):
    L = encrypt_block(bytes(bytearray(BLOCK_SIZE)), k)

    LHigh = unpack('>L', L[:4])[0]
    LLow = unpack('>L', L[4:])[0]

    K1High = ((LHigh << 1) | (LLow >> 31)) & 0xFFFFFFFF
    K1Low = (LLow << 1) & 0xFFFFFFFF

    if (LHigh >> 31):
        K1Low ^= 0x1B

    K2High = ((K1High << 1) | (K1Low >> 31)) & 0xFFFFFFFF
    K2Low = ((K1Low << 1)) & 0xFFFFFFFF

    if (K1High >> 31):
        K2Low ^= 0x1B

    K1 = bytearray(pack('>LL', K1High, K1Low))
    K2 = bytearray(pack('>LL', K2High, K2Low))

    return K1, K2


def xor_128(n1, n2):
    j = bytearray()
    for i in range(len(n1)):
        j.append(n1[i] ^ n2[i])
    return j


def pad(n):
    padLen = BLOCK_SIZE - len(n)
    return n + b'\x80' + b'\x00'*(padLen-1)


def encrypt_block(block, key):
    cipher = blowfish.Cipher(key)
    return cipher.encrypt_block(block)


def encrypt_ofb(plain_text, key):
    # Generate IV
    original_iv = secrets.token_bytes(BLOCK_SIZE)
    iv = original_iv

    # Generate CMAC
    cmac_key = secrets.token_bytes(16)
    cmac = gen_cmac(cmac_key, plain_text, len(plain_text))

    text_length = len(plain_text)
    # Covert text to list of blocks
    plain_blocks = [plain_text[i:i+BLOCK_SIZE]
                    for i in range(0, text_length, BLOCK_SIZE)]

    # Encrypt blocks
    cipher_blocks = []
    for block in plain_blocks:
        cipher_iv = encrypt_block(iv, key)
        cipher_block = byte_xor(block, cipher_iv)
        iv = cipher_iv
        cipher_blocks.append(cipher_block)

    cypher_text = bytearray(0)
    for block in cipher_blocks:
        cypher_text += block

    # Add cmac key and cmac to cypher text
    cypher_text = cmac_key + cmac + cypher_text

    # Add iv to cypher text
    cypher_text = original_iv + cypher_text

    return cypher_text


def decrypt_ofb(cipher_text, key):
    # Get iv from cypher text
    iv = cipher_text[:BLOCK_SIZE]
    cipher_text = cipher_text[BLOCK_SIZE:]

    # Get cmac key and cmac to cypher text
    cmac_key = cipher_text[:16]
    cmac = cipher_text[16:24]
    cipher_text = cipher_text[24:]

    cipher_length = len(cipher_text)
    # Convert text to list of blocks
    cipher_blocks = [cipher_text[i:i+BLOCK_SIZE]
                     for i in range(0, cipher_length, BLOCK_SIZE)]

    # Decrypt blocks
    plain_blocks = []
    for block in cipher_blocks:
        plain_iv = encrypt_block(iv, key)
        plain_block = byte_xor(block, plain_iv)
        iv = plain_iv
        plain_blocks.append(plain_block)

    plain_text = bytearray(0)
    for block in plain_blocks:
        plain_text += block

    try:
        assert cmac == gen_cmac(cmac_key, plain_text, len(plain_text))
        print("\nThe message is authentic!")
    except AssertionError:
        print("\nWARNING! The message is NOT authentic!")

    return plain_text


def main(dataFile, keyFile, operation='e', mode='cbc'):
    OPERATION = ENCRYPT if operation.lower() == 'e' else DECRYPT
    KEY = bytes.fromhex(read_file(keyFile))
    MODE = CBC if mode.upper() == CBC else OFB

    read_data = text_to_byte_array(read_file(dataFile)) \
        if OPERATION == ENCRYPT else read_file_binary(dataFile)

    if MODE == CBC:
        output_data = encrypt_cbc(read_data, KEY) if OPERATION == ENCRYPT \
            else decrypt_cbc(read_data, KEY)
    elif MODE == OFB:
        output_data = encrypt_ofb(read_data, KEY) if OPERATION == ENCRYPT \
            else decrypt_ofb(read_data, KEY)

    write_file_binary(output_data) if OPERATION == ENCRYPT \
        else write_file(output_data.decode("utf-8"))

    output_operation = 'Encryption' if OPERATION == ENCRYPT else 'Decryption'
    output_name = OUTPUT_ENCRYPTED if OPERATION == ENCRYPT \
        else OUTPUT_DECRYPTED

    print(
        f'\n{output_operation} successful!\nGenerated output: {output_name}'
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='encrypt/decrypt file with \
        hex key using CBC with cypher text stealing')
    parser.add_argument(
        'operation', help='operation: e for encrypt; d for decrypt')
    parser.add_argument('dataFile', help='file to be encrypted/decrypted')
    parser.add_argument('keyFile', help='file with hex key')
    parser.add_argument('mode', help='chaining mode: cbc or ofb')
    args = parser.parse_args()

    # Executes script with variables
    main(operation=args.operation, dataFile=args.dataFile,
         keyFile=args.keyFile, mode=args.mode)
