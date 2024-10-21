import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def load_public_key(public_key_file):
    # Load public key from PEM file
    with open(public_key_file, 'rb') as key_file:
        public_key = load_pem_public_key(key_file.read())
    return public_key

def encrypt_data(public_key, data, block_size):
    encrypted_data = b""
    # Encrypt data in chunks according to the block size
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.PKCS1v15()
        )
        encrypted_data += encrypted_chunk
    return encrypted_data

def main():
    if len(sys.argv) != 4:
        print("Usage: python encrypt_file.py <original_file> <public_key_file> <encrypted_file>")
        sys.exit(1)

    original_file = sys.argv[1]
    public_key_file = sys.argv[2]
    encrypted_file = sys.argv[3]

    # Load the public key
    public_key = load_public_key(public_key_file)
    key_size = public_key.key_size // 8  # Convert bits to bytes
    block_size = key_size - 11  # PKCS#1 padding reduces the block size

    # Read the original file to encrypt
    with open(original_file, 'rb') as f:
        file_data = f.read()

    # Encrypt the file data
    encrypted_data = encrypt_data(public_key, file_data, block_size)

    # Save the encrypted data to the output file
    with open(encrypted_file, 'wb') as f:
        f.write(encrypted_data)

    print(f"File '{original_file}' has been encrypted and saved to '{encrypted_file}'.")

if __name__ == "__main__":
    main()
