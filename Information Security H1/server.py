import socket
import threading
import random
import struct
import sys
import time

from utility import *

key_master = None
key_cbc = None
key_cfb = None
init_vector = None
method = None


def generate_components():
    global key_master, key_cfb, key_cbc, init_vector

    key_master = []
    key_cbc = []
    key_cfb = []
    init_vector = []
    for i in range(16):
        key_master.append(random.randint(0, 255))
        key_cbc.append(random.randint(0, 255))
        key_cfb.append(random.randint(0, 255))
        init_vector.append(random.randint(0, 255))

    print("Key Master: ", end="")
    print_hexa(key_master)
    print("Key CBC: ", end="")
    print_hexa(key_cbc)
    print("Key CFB: ", end="")
    print_hexa(key_cfb)
    print("Init Vector: ", end="")
    print_hexa(init_vector)


generate_components()
random.seed()
my_lock = threading.Lock()
e = threading.Event()
e.clear()
threads = []
client_count = 0
notification = []
notified_A = False

nr_blocks = [None, None, None, None]


def worker(cs):
    global my_lock, client_count, e
    global key_master, key_cfb, key_cbc, init_vector, method, notification, notified_A, nr_blocks

    my_id_count = client_count
    print('client #', client_count, 'from: ', cs.getpeername(), cs)

    if my_id_count == 1:
        message = "A"
    elif my_id_count == 2:
        message = "B"
    else:
        message = "U"
        time.sleep(1)
        cs.close()
        print("Worker Thread ", my_id_count, " end")

    cs.send(bytes(message, 'ascii'))
    print('Sent identity')

    cs.send(bytes(key_master))
    print('Sent key_master')

    cs.send(aes_encrypt_ecb(bytes(init_vector), bytes(key_master)))
    print('Sent init_vector')

    if my_id_count == 1:
        method = aes_decrypt_ecb(cs.recv(1024), bytes(key_master)).decode('ascii')[:-13]
        print("A chose method:", method)

    elif my_id_count == 2:
        encripted_method = aes_encrypt_ecb(bytes(method + ("A"*13), 'ascii'), bytes(key_master))
        cs.send(bytes(encripted_method))
    print('Communicated the method chosen by A to B')

    if method == 'CFB':
        cs.send(aes_encrypt_ecb(bytes(key_cfb), bytes(key_master)))
    else:
        cs.send(aes_encrypt_ecb(bytes(key_cbc), bytes(key_master)))
    print('Sent method key')

    if my_id_count == 2:
        notification = cs.recv(1024)
        notified_A = True
    elif my_id_count == 1:
        while not notified_A:
            pass

        cs.send(notification)

    nr_blocks_text = cs.recv(1024).decode("ascii")
    nr_blocks_crypted = cs.recv(1024).decode("ascii")
    print("Nr_Blocks_Text", nr_blocks_text)
    print("Nr_Blocks_Crypted", nr_blocks_crypted)

    if my_id_count == 1:
        nr_blocks[0] = nr_blocks_text
        nr_blocks[1] = nr_blocks_crypted
    elif my_id_count == 2:
        nr_blocks[2] = nr_blocks_text
        nr_blocks[3] = nr_blocks_crypted

    """
    connected = True
    while connected:
        connected = True
    """

    time.sleep(1)
    cs.close()
    e.set()
    print("Worker Thread ", my_id_count, " end")


def end_server():
    global my_lock, threads, e, client_count, key_master, notified_A, notification
    while True:
        e.wait()
        for t in threads:
            t.join()
        print("All threads are finished now")
        e.clear()

        if nr_blocks[0] == nr_blocks[2]:
            print("The plain texts have the same amount of blocks")
        else:
            print("The plain texts don't have the same amount of blocks, probably an error has occurred at decrypting")

        if nr_blocks[1] == nr_blocks[3]:
            print("The encrypted texts have the same amount of blocks")
        else:
            print("The encrypted texts  don't have the same amount of blocks, probably an error has occurred at "
                  "encrypting")

        print("---------------------------------")
        print("Ending Server")

        import os
        os._exit(0)
        """
        my_lock.acquire()
        threads = []
        client_count = 0
        my_lock.release()
        generate_components()
        notification = []
        notified_A = False
        """


if __name__ == '__main__':
    try:
        rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rs.bind(('0.0.0.0', 1234))
        rs.listen(5)
    except socket.error as msg:
        print(msg.strerror)
        exit(-1)
    t = threading.Thread(target=end_server, daemon=True)
    t.start()
    while True:
        client_socket, addrc = rs.accept()
        t = threading.Thread(target=worker, args=(client_socket,))
        threads.append(t)
        client_count += 1
        t.start()
