import socket, struct, random, sys, time
from utility import *


def client_a(s):
    print("I am A")
    connected = True

    key_master = s.recv(1024)
    print("Key Master: ", end="")
    print_hexa(key_master)

    encripted_init_vector = s.recv(1024)
    init_vector = aes_decrypt_ecb(encripted_init_vector, key_master)
    print("Init Vector: ", end="")
    print_hexa(init_vector)

    methods = ["CBC", "CFB"]
    chosen_method = random.randint(0, 1)
    method = methods[chosen_method]
    print("I have chosen: ", method)

    encripted_method = aes_encrypt_ecb(bytes(method + ("A"*13), 'ascii'), key_master)

    s.send(encripted_method)
    print("Succesfully sent the method to the Key Master")

    encripted_method_key = s.recv(1024)
    method_key = aes_decrypt_ecb(encripted_method_key, key_master)
    print(method, "Key: ", end="")
    print_hexa(method_key)

    notification = s.recv(1024)

    print("Trying to connect to B")
    pr = socket.create_connection(('localhost', 2345))
    print("Connected to B")

    file_name = "file.txt"
    file = open(file_name, "rb")
    text = file.read()
    print("Read file:", file_name)

    if method == "CBC":
        cipher_cbc = AES_CBC(method_key, init_vector)
        crypted_message = cipher_cbc.encrypt(text)
    else:
        cipher_cfb = AES_CFB(method_key, init_vector)
        crypted_message = cipher_cfb.encrypt(text)
    print("Crypted file's content:")

    pr.send(crypted_message)
    print("Sent the file to B")

    nr_blocks_text = len(text) // 16
    if nr_blocks_text % 16:
        nr_blocks_text += 1
    nr_blocks_cripted = len(crypted_message) // 16
    if nr_blocks_cripted % 16:
        nr_blocks_cripted += 1

    s.send(bytes(str(nr_blocks_text), "ascii"))
    s.send(bytes(str(nr_blocks_cripted), "ascii"))
    print("Sent the number of blocks from file to Key Master")


def client_b(s):
    print("I am B")
    connected = True

    key_master = s.recv(1024)
    print("Key Master: ", end="")
    print_hexa(key_master)

    encripted_init_vector = s.recv(1024)
    init_vector = aes_decrypt_ecb(encripted_init_vector, key_master)
    print("Init Vector: ", end="")
    print_hexa(init_vector)

    method = aes_decrypt_ecb(s.recv(1024), bytes(key_master)).decode('ascii')[:-13]
    print("The wished method: ", method)

    encripted_method_key = s.recv(1024)
    method_key = aes_decrypt_ecb(encripted_method_key, key_master)
    print(method, "Key: ", end="")
    print_hexa(method_key)

    print("Trying to open own server to communicate with A")
    rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rs.bind(('0.0.0.0', 2345))
    rs.listen(1)
    # Trigger alarm to notify A when to connect through KM
    s.send(b"I became a server!")
    print("Sent notification to Key Master to announce A to connect to B")
    peer_socket, peer_addr = rs.accept()

    crypted_message = peer_socket.recv(1024*1024)

    print("Received the encrypted message")

    if method == "CBC":
        cipher_cbc = AES_CBC(method_key, init_vector)
        plain_message = cipher_cbc.decrypt(crypted_message)
    else:
        cipher_cfb = AES_CFB(method_key, init_vector)
        plain_message = cipher_cfb.decrypt(crypted_message)

    print("The decrypted message is:")
    print(plain_message)

    nr_blocks_text = len(plain_message) // 16
    if nr_blocks_text % 16:
        nr_blocks_text += 1
    nr_blocks_cripted = len(crypted_message) // 16
    if nr_blocks_cripted % 16:
        nr_blocks_cripted += 1

    s.send(bytes(str(nr_blocks_text), "ascii"))
    s.send(bytes(str(nr_blocks_cripted), "ascii"))
    print("Sent the number of blocks from file to Key Master")


if __name__ == '__main__':
    try:
        s = socket.create_connection(('localhost', 1234))
    except socket.error as msg:
        print("Error: ", msg.strerror)
        exit(-1)

    data = s.recv(1024)
    received = data.decode('ascii')

    if received == "A":
        client_a(s)
    elif received == "B":
        client_b(s)


#    input("Press Enter")
