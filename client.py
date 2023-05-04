import hashlib
import socket
import random
from Crypto.PublicKey import DSA

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8888))

try:
    key = DSA.generate(2048)
    f = open("./key.pem", "wb")
    f.write(key.exportKey())
    f.close()

    f = open("key.pem", "rb")  # File opened in read byte mode
    key = DSA.import_key(f.read())  # Key is read
    p = key.p
    q = key.q
    assert ((p-1)%q==0)
    exponent = int(p-1)//int(q)
    e0 = p - 2
    e1 = pow(e0, exponent, p)
    assert (e1 != 1)
    val = pow(e1, q, p)
    assert (val == 1)
    d = random.randint(1, q - 1)        # private key
    e2 = pow(e1, d, p)      # public key
    print("Input count: ")
    r = int(input())  # random number generation as per range
    x = pow(e1, r, p)  # part to append to the message
    orig_message = "Bushumov"
    message = orig_message + str(x)
    digest = hashlib.sha256(message.encode())  # digest generation
    S1 = digest.hexdigest()  # digest retrieval
    S2 = (r + (d * int(S1, 16))) % q  # calculating other part of the signature

    data = str(e1) + "," + str(S2) + "," + str(p) + "," + str(e2) + "," + str(S1) + "," + str(orig_message)
    sock.send(data.encode())

    print('\n')
    print(f'p: {p}')
    print(f'q: {q}')
    print(f'd: {d}')
    print(f'r: {r}')
    print(f'message: {orig_message}')
    print('\n')

    Y = sock.recv(30)
    mess = Y.decode()
    print(f'Answer: {Y.decode()}')

finally:
    sock.close()
