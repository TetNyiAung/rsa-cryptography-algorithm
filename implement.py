import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Generate RSA keys for a user
def generate_rsa_keys():
    """Generate and return public and private keys for RSA encryption."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt the file and sign it
def encrypt_and_sign_message(message, public_key, private_key, user_name):
    """Encrypt a message and add a digital signature."""
    message_bytes = message.encode('utf-8')

    # Create message hash
    message_hash = SHA256.new(message_bytes)

    # Sign the hash using the private key
    private_rsa_key = RSA.import_key(private_key)
    signature = pkcs1_15.new(private_rsa_key).sign(message_hash)

    # Encrypt the message using the public key
    public_rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_rsa_key)
    encrypted_message = cipher.encrypt(message_bytes)

    # Save the encrypted message and signature to files
    encrypted_file_path = f"{user_name}_message.enc"
    signature_file_path = f"{user_name}_message.sig"

    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_message)
    with open(signature_file_path, 'wb') as f:
        f.write(signature)

    print(f"{user_name}: Message encrypted and saved as '{encrypted_file_path}'.")
    print(f"{user_name}: Signature saved as '{signature_file_path}'.")
    return encrypted_file_path, signature_file_path

# Verify and decrypt the message
def verify_and_decrypt_message(encrypted_file_path, signature_file_path, private_key, sender_public_key, user_name):
    """Verify the signature and decrypt the message."""
    try:
        with open(encrypted_file_path, 'rb') as f:
            encrypted_message = f.read()
        with open(signature_file_path, 'rb') as f:
            signature = f.read()

        # Decrypt the message
        private_rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_rsa_key)
        decrypted_message = cipher.decrypt(encrypted_message)

        # Verify the signature
        sender_rsa_key = RSA.import_key(sender_public_key)
        message_hash = SHA256.new(decrypted_message)
        pkcs1_15.new(sender_rsa_key).verify(message_hash, signature)

        print(f"{user_name}: Decryption successful! The message has not been tampered with.")
        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
    except ValueError as e:
        print(f"{user_name}: Tampering detected or invalid message! {e}")
        raise
    except Exception as e:
        print(f"{user_name}: An unexpected error occurred: {e}")
        raise

# Main execution flow
if __name__ == "__main__":
    print("=== RSA Encryption & Digital Signature ===")

    # Generate keys for Patrick and Pandora if not already present
    if not os.path.exists("patrick_private_key.pem"):
        patrick_private_key, patrick_public_key = generate_rsa_keys()
        pandora_private_key, pandora_public_key = generate_rsa_keys()

        # Save keys to files
        with open("patrick_private_key.pem", 'wb') as f:
            f.write(patrick_private_key)
        with open("patrick_public_key.pem", 'wb') as f:
            f.write(patrick_public_key)
        with open("pandora_private_key.pem", 'wb') as f:
            f.write(pandora_private_key)
        with open("pandora_public_key.pem", 'wb') as f:
            f.write(pandora_public_key)
    else:
        # Load existing keys
        with open("patrick_private_key.pem", 'rb') as f:
            patrick_private_key = f.read()
        with open("patrick_public_key.pem", 'rb') as f:
            patrick_public_key = f.read()
        with open("pandora_private_key.pem", 'rb') as f:
            pandora_private_key = f.read()
        with open("pandora_public_key.pem", 'rb') as f:
            pandora_public_key = f.read()

    # Encrypt and sign the messages only if encrypted files do not already exist
    if not os.path.exists("patrick_message.enc") or not os.path.exists("pandora_message.enc"):
        # Patrick enters a message
        patrick_message = input("Patrick: Enter your message: ")
        encrypt_and_sign_message(patrick_message, pandora_public_key, patrick_private_key, "patrick")

        # Add a blank line between Patrick and Pandora's sections
        print("\n" + "=" * 40 + "\n")

        # Pandora enters a message
        pandora_message = input("Pandora: Enter your message: ")
        encrypt_and_sign_message(pandora_message, patrick_public_key, pandora_private_key, "pandora")

        print("\nMessages have been encrypted and signed.")
        exit(0)
    else:
        print("\nEncrypted files already exist. Verifying and decrypting the messages...")

    # Add a blank line between verification and decryption sections
    print("\n" + "=" * 40 + "\n")

    # Verify and decrypt Patrick's message for Pandora
    try:
        verify_and_decrypt_message("patrick_message.enc", "patrick_message.sig", pandora_private_key, patrick_public_key, "Patrick")
    except Exception as e:
        print(f"Failed to verify/decrypt Patrick's message: {e}")

    # Add a blank line between Patrick and Pandora's decryption sections
    print("\n" + "=" * 40 + "\n")

    # Verify and decrypt Pandora's message for Patrick
    try:
        verify_and_decrypt_message("pandora_message.enc", "pandora_message.sig", patrick_private_key, pandora_public_key, "Pandora")
    except Exception as e:
        print(f"Failed to verify/decrypt Pandora's message: {e}")
