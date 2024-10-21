import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def load_private_key(private_key_file):
    # Load private key from PEM file
    with open(private_key_file, 'rb') as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)
    return private_key

def decrypt_data(private_key, data, key_size):
    decrypted_data = b""
    # Decrypt data in chunks according to the key size
    for i in range(0, len(data), key_size):
        chunk = data[i:i + key_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.PKCS1v15()
        )
        decrypted_data += decrypted_chunk
    return decrypted_data

def main():
    if len(sys.argv) != 4:
        print("Usage: python decrypt_file.py <encrypted_file> <private_key_file> <decrypted_output_file>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    private_key_file = sys.argv[2]
    decrypted_file = sys.argv[3]

    # Load the private key
    private_key = load_private_key(private_key_file)
    key_size = private_key.key_size // 8  # Convert bits to bytes

    # Read the encrypted file
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the encrypted data
    decrypted_data = decrypt_data(private_key, encrypted_data, key_size)

    # Save the decrypted data to the output file
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"File '{encrypted_file}' has been decrypted and saved to '{decrypted_file}'.")

if __name__ == "__main__":
    main()
