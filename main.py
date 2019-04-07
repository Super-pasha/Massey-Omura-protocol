import cryptutils
import asnapi
import socket
import sys
import os

RECV_BUF = 1024
PRIME_BITS = 1024
DES3_KEY_BITS = 192


def assert_rcv(data):
    if not data:
        raise Exception('data is None')

def transfer_file(sock, filename, length, key_int):
    key = cryptutils.int_to_bytes(key_int)
    if length % RECV_BUF == 0:
        chunks = length // RECV_BUF
    else:
        chunks = length // RECV_BUF + 1

    with open(filename, 'rb') as f:
        for _ in range(chunks):
            data = f.read(RECV_BUF)
            sock.send(cryptutils.des_encrypt(data, key))

def client(ip_addr, port, filename):

    sock = socket.socket()
    sock.settimeout(10)

    sock.connect((ip_addr, port))
    print('\nConnected to server %s:%s' % (ip_addr, port))

    # client generates prime and des key
    # then client sends key to server via Massey - Omura protocol
    print('--- Generating parameters ---')
    key_int = cryptutils.getrandbits(DES3_KEY_BITS)
    prime = cryptutils.get_big_prime(PRIME_BITS)
    client = cryptutils.MasseyOmuraProtocol(prime)

    # step 1: client encrypts key with its own e
    print('\t--- Performing client step 1 ---')
    encrypted_key = client.encrypt_msg(key_int)
    asn1_blob = asnapi.export_client_msg1(prime, prime, encrypted_key)
    sock.send(asn1_blob)

    # step 2: client recieves its data back from server
    # but now it's encrypted with server's e,
    # so it's time to remove client's lock
    print('\t--- Performing client step 2 ---')
    asn1_blob = sock.recv(RECV_BUF)
    assert_rcv(asn1_blob)
    parsed_asn1 = asnapi.import_server_msg1(asn1_blob)
    unlocked_data = client.decrypt_msg(parsed_asn1['data'])

    # step 3: send file attributes
    if '.' in filename:
        filename_srv = filename[:filename.rfind('.')] + '.srv.'
        filename_srv += filename.split('.')[-1]
    else:
        filename_srv = filename + '.srv'

    length = os.path.getsize(filename)
    asn1_blob = asnapi.export_client_msg2(
        unlocked_data, length, filename_srv.encode())
    sock.send(asn1_blob)

    # step 4: transmit file
    # recv to synchronize client and server
    if sock.recv(RECV_BUF).decode() != 'Ok':
        raise Exception('Error transfering file')
    print('\t--- Transfering file... ---')
    transfer_file(sock, filename, length, key_int)
    print('--- Done ---')


def recieve_file(conn, filename, length, key):
    
    open(filename, 'w').close()
    if length % RECV_BUF == 0:
        chunks = length // RECV_BUF
    else:
        chunks = length // RECV_BUF + 1

    with open(filename, 'ab') as f:
        for _ in range(chunks - 1):
            f.write(cryptutils.des_decrypt(
                conn.recv(RECV_BUF), key))

        last_chunk_n = length % RECV_BUF or RECV_BUF
        f.write(cryptutils.des_decrypt(
                conn.recv(RECV_BUF), key)[:last_chunk_n])

def server(ip_addr, port):

    sock = socket.socket()
    sock.bind((ip_addr, port))
    sock.listen(1)

    print('Server is running on %s:%s' % (ip_addr, str(port)))

    while True:

        conn, addr = sock.accept()
        print('\nConnected: ', addr)

        try:
            asn1_blob = conn.recv(RECV_BUF)
            assert_rcv(asn1_blob)

            parsed_asn1 = asnapi.import_client_msg1(asn1_blob)
            data = parsed_asn1['data']
            prime = parsed_asn1['prime']

            # step 1: server encrypts client's data with its own e
            print('\t--- Performing server step 1 ---')
            server = cryptutils.MasseyOmuraProtocol(prime)
            encrypted_data = server.encrypt_msg(data)
            asn1_blob = asnapi.export_server_msg1(encrypted_data)
            conn.send(asn1_blob)

            # step 2: server decrypts client's data with its own d
            print('\t--- Performing server step 2 ---')
            asn1_blob = conn.recv(RECV_BUF)
            assert_rcv(asn1_blob)

            parsed_asn1 = asnapi.import_client_msg2(asn1_blob)
            data = parsed_asn1['data']
            length = parsed_asn1['length']
            filename = parsed_asn1['name']

            # step 3: decrypt main message with decrypted_key
            decrypted_key = server.decrypt_msg(data)
            key = cryptutils.int_to_bytes(decrypted_key)
            print('\t--- Key is decrypted ---')

            # step 4: recieve file
            # synchronize with client
            print('\t--- Recieving file... ---')
            conn.send('Ok'.encode())
            recieve_file(conn, filename, length, key)
            print('\t--- Done. Closing connection ---')

        except Exception as e:
            print('Error occured: %s. Closing connection\n' % str(e))

        finally:
            conn.close()


def usage():
    print('Usage:')
    print('\tClient mode: main.py client <ip> <port> <filename>')
    print('\tServer mode: main.py server <ip> <port>')


if __name__ == '__main__':
    if len(sys.argv) == 4 or len(sys.argv) == 5:
        mode = sys.argv[1]
        if mode == 'client':
            filename = sys.argv[4]
            client(sys.argv[2], int(sys.argv[3]), filename)
        elif mode == 'server':
            server(sys.argv[2], int(sys.argv[3]))
        else:
            usage()
    else:
        usage()


# for i in range(10000):
#
#    print(i)
#    prime = cryptutils.get_big_prime(PRIME_BITS)
#
#    server = cryptutils.MasseyOmuraProtocol(prime)
#    client = cryptutils.MasseyOmuraProtocol(prime)
#
#    data_int = cryptutils.getrandbits(192)
#    encrypted_data_cli = client.encrypt_msg(data_int)
#    encrypted_data_srv = server.encrypt_msg(encrypted_data_cli)
#    decrypted_data_cli = client.decrypt_msg(encrypted_data_srv)
#    decrypted_data_srv = server.decrypt_msg(decrypted_data_cli)
#
#    assert data_int == decrypted_data_srv
#
#assert False
