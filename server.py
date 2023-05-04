import hashlib
import random
import socket
from Crypto.PublicKey import DSA

def verify(e1, S2, p, e2, S1, message):
    x_dash = (pow(e1, S2, p) * pow(e2, -(int(S1, 16)), p)) % p
    received_message = message
    message_dash = received_message + str(x_dash)
    digest_dash = hashlib.sha256(message_dash.encode())
    S1_dash = digest_dash.hexdigest()
    if(S1==S1_dash):
        return True
    else:
        return False

def check_key():
    f = open("key.pem", "rb")
    key = DSA.import_key(f.read())
    print(key)

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 8888))
server_socket.listen(5)
print("Server started...")


while True:
    client_sockets, addr = server_socket.accept()
    try:
        print('Connected: ', addr)
        while True:
            rec = client_sockets.recv(8192)
            msg_received = rec.decode()
            message = msg_received.split(',')

            e1 = int(message[0])
            S2 = int(message[1])
            p = int(message[2])
            e2 = int(message[3])
            S1 = str(message[4])
            received_message = str(message[5])

            is_verified = verify(e1, S2, p, e2, S1, received_message)

            if (is_verified == True):
                X = "Signature Verified!"
                print(X)
                client_sockets.sendall(X.encode())
            else:
                X = "Signature Invalid!"
                print(X)
                client_sockets.sendall(X.encode())

            break

    finally:
        client_sockets.close()
        print("Server dissconnected")
