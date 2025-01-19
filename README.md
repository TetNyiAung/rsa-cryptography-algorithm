# rsa-cryptography-algorithm
This Python code implements a secure communication system using RSA encryption and digital signatures to ensure confidentiality, integrity, and authenticity of messages exchanged between two users, Patrick and Pandora.

Step 1: Setting Up the Environment
    Install Required Libraries: 
        Ensure you have the pycryptodome library installed.
        You can install it using:  pip install pycryptodome 
    Create the Code File:
        Copy and paste the code into a .py file, e.g., implement.py.

Step 2: Understand the Flow
    The code facilitates communication between two users, Patrick and Pandora, with the following key functionalities:
        Key Generation:
            Each user generates their RSA public and private keys.
            Keys are saved into files (patrick_private_key.pem, patrick_public_key.pem, pandora_private_key.pem, pandora_public_key.pem) for later use.
        Message Encryption and Signing:
            Patrick encrypts his message with Pandora's public key and signs it with his private key.
            Pandora encrypts her reply with Patrick's public key and signs it with her private key.
        Decryption and Verification:
            Upon receiving the message, the recipient decrypts it with their private key and verifies the signature using the sender’s public key.
        Manual Tampering:
            After encryption, the program pauses to allow manual tampering with the encrypted files for integrity testing.

Step 3: Running the Code
    Execute the Program:
        Input Messages:
            When prompted, type a message for Patrick and Pandora during their respective turns.
        Observe Outputs:
            The program will display the progress:
                Key generation for both users.
                Encryption and signature file creation.
                A prompt to tamper with the encrypted files manually.
                Decryption and verification results after execution.
        Manual Tampering:
            After the encryption step, modify the encrypted file content (patrick_to_pandora.enc or pandora_to_patrick.enc) to simulate tampering.
            Add random characters, remove portions, or otherwise alter the file using a text editor.
        Rerun to Test Integrity:
            Run the program again.
            The decryption and verification steps will detect tampered files and display errors indicating potential issues with integrity or authenticity.

Step 4: Code Details
    Functions Overview:
        Key Generation:
            generate_rsa_keys(): Creates RSA key pairs and saves them into files for both Patrick and Pandora.
        Message Encryption and Signing:
            encrypt_and_sign_message(): Encrypts the plaintext message and generates a digital signature.
        Decryption and Verification:
            decrypt_and_verify_message(): Splits the encrypted file, decrypts the message, and verifies the signature to ensure the message is untampered.
        Hashing:
            hash_file(): Creates a SHA-256 hash of a file for integrity checks.
            Files Used:
            Patrick's Keys:
            patrick_private_key.pem, patrick_public_key.pem
            Pandora's Keys:
            pandora_private_key.pem, pandora_public_key.pem
            Encrypted Files:
            patrick_to_pandora.enc, pandora_to_patrick.enc

Step 5: Results
    Untampered Files:
        If no tampering occurs, the program will successfully decrypt and verify the files, showing outputs indicating integrity and authenticity.
    Tampered Files:
        If tampering occurs, errors such as "Tampering detected" or "Signature verification failed" will be displayed, confirming that the files have been altered.
