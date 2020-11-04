from Crypto.Cipher import AES


def aes_encrypt_ecb(plain_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plain_text)


def aes_decrypt_ecb(crypted_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(crypted_text)


def add_padding_to_block(block):
    pad_number = 16 - len(block)

    for i in range(pad_number):
        block.append(pad_number)

    return block


def bytes_xor(block1, block2):
    result = []

    for i in range(16):
        result.append(block1[i] ^ block2[i])

    return bytes(result)


def print_hexa(binary_text):
    for c in binary_text:
        print("{:02X}".format(c), end=" ")

    print()


def get_blocks_16(binary_text, add_padding=True):
    blocks = []
    i = 0

    block = []
    for c in binary_text:
        block.append(c)
        i += 1

        if i % 16 == 0:
            blocks.append(block)
            block = []

    if add_padding:
        block = add_padding_to_block(block)

    if len(block):
        blocks.append(block)

    return blocks


class AES_CBC:
    def __init__(self, key, init_vector):
        self.key = bytes(key)
        self.init_vector = bytes(init_vector)

    def encrypt(self, plain_text):
        blocks = get_blocks_16(plain_text)

        cypher_text = b""

        i = 0
        for block in blocks:
            block_bytes = bytes(block)

            if i == 0:
                xorSum = bytes_xor(self.init_vector, block_bytes)
            else:
                xorSum = bytes_xor(last_cypher_block, block_bytes)

            last_cypher_block = aes_encrypt_ecb(xorSum, self.key)
            cypher_text += last_cypher_block
            i += 1

        return cypher_text

    def decrypt(self, encrypted_text):
        blocks = get_blocks_16(encrypted_text, add_padding=False)

        plain_text = b""

        i = 0
        last_block = []
        for block in blocks:
            decrypted = aes_decrypt_ecb(bytes(block), self.key)

            if i == 0:
                xor_sum = bytes_xor(self.init_vector, decrypted)
            else:
                xor_sum = bytes_xor(bytes(last_block), decrypted)

            plain_text += xor_sum

            last_block = block
            i += 1

        padding_value = plain_text[-1]
        return plain_text[:-padding_value]


class AES_CFB:
    def __init__(self, key, init_vector):
        self.key = bytes(key)
        self.init_vector = bytes(init_vector)

    def encrypt(self, plain_text):
        blocks = get_blocks_16(plain_text)

        cypher_text = b""
        i = 0

        last_xor_sum = []
        for block in blocks:
            if i == 0:
                encrypted = aes_encrypt_ecb(self.init_vector, self.key)
            else:
                encrypted = aes_encrypt_ecb(last_xor_sum, self.key)

            xor_sum = bytes_xor(block, encrypted)
            cypher_text += xor_sum

            last_xor_sum = xor_sum
            i += 1

        return cypher_text

    def decrypt(self, encrypted_text):
        blocks = get_blocks_16(encrypted_text, add_padding=False)

        plain_text = b""
        i = 0

        last_block = []
        for block in blocks:
            if i == 0:
                decrypted = aes_encrypt_ecb(self.init_vector, self.key)
            else:
                decrypted = aes_encrypt_ecb(bytes(last_block), self.key)

            xor_sum = bytes_xor(block, decrypted)
            plain_text += xor_sum

            last_block = block
            i += 1

        padding_value = plain_text[-1]
        return plain_text[:-padding_value]


if __name__ == '__main__':
    key = b"AKRIEL_VS_WORLDS"
    init_vector = b"A" * 16

    text = b"0123456789ABCDEXXX"

    cipher_cbc = AES_CBC(key, init_vector)
    result = cipher_cbc.encrypt(text)
    message = cipher_cbc.decrypt(result)
    print_hexa(result)
    print_hexa(message)

    cipher_cfb = AES_CFB(key, init_vector)
    result = cipher_cfb.encrypt(text)
    message = cipher_cfb.decrypt(result)
    print_hexa(result)
    print_hexa(message)