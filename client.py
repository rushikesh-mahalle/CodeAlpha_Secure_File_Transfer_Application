import argparse
import os
import socket
import logging
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import getpass

logging.basicConfig(filename='client.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main(input_file, output_file):
    key = b"MySecureKey12345"  # any 16-byte key
    nonce = b"abcdefs090078601"  # any 16-byte nonce

    cipher = AES.new(key, AES.MODE_EAX, nonce)

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", 8000))
        logging.info("Connected to server on port 8000")

        if not os.path.exists(input_file):
            logging.error(f"Input file '{input_file}' does not exist.")
            return

        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        client.send(username.encode())
        client.send(password.encode())
        auth_response = client.recv(1024).decode()
        if auth_response != "AUTH_SUCCESS":
            logging.error("Authentication failed")
            return
        logging.info("Authentication successful")

        with open(input_file, "rb") as f:
            data = f.read()
            logging.info(f"Read {len(data)} bytes from '{input_file}'")

        
        encrypted = cipher.encrypt(data)
        logging.info("Data encrypted")

        hmac = HMAC.new(key, encrypted, SHA256).digest()

        client.send(output_file.encode())
        client.sendall(encrypted)
        client.sendall(hmac)
        client.send(b"\n")
        logging.info("Sent encrypted data, HMAC, and end tag to server")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        
    finally:
        client.close()
        logging.info("Connection closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt and send a file to the server.")
    parser.add_argument("input_file", help="The path to the file to be sent.")
    parser.add_argument("output_file", help="The name of the file to save on the server.")

    args = parser.parse_args()
    main(args.input_file, args.output_file)
