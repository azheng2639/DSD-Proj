# DSD-Proj

nb.ipynb offers a step my step explanantion and example of the DH key exchange implementation

main.py is a standalone program for users to utilize DH. Each session of this script acts as its own user with its own public and private key generated. Users can see their public key, the private key is abstracted. With another session, a shared secret can be generated using the other session's public key. Once this shared secret is created, users can encrypt and decrypt messages seemlessly by exchanging the cyphertext