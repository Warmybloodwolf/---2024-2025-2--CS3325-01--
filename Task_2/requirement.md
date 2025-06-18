Goal : Perform a CCA2 attack on textbook RSA

Textbook RSA is elegant, but has no semantic security.

An adaptive chosen-ciphertext attack (abbreviated as CCA2) is an interactive form of chosen-ciphertext attack in which an attacker sends a number of ciphertexts to be decrypted, then uses the results of these decryptions to select subsequent ciphertexts.

The goal of this attack is to gradually reveal information about an encrypted message, or about the decryption key itself.

---

Refer an existing work for the implementation: (Details of this attack can be found in Chap 4.)

Knockel J, Ristenpart T, Crandall J. When textbook RSA is used to protect the privacy of hundreds of millions of users[J]. arXiv preprint arXiv:1802.03367, 2018. (https://arxiv.org/abs/1802.03367)

---

Server-client communication:

Client:
1. generate a 128-bit AES session key for the session.
2. encrypt this session key using a 1024-bit RSA public key.
3. use the AES session key to encrypt the WUP request.
4. send the RSA-encrypted AES session key and the encrypted WUP request to the server.

Server:

1. decrypt the RSA-encrypted AES key it received from the client.
2. choose the least significant 128 bits of the plaintext to be the AES session key.
3. decrypt the WUP request using the AES session key.
4. send an AES-encrypted response if the WUP request is valid.

---

In this attack, the server knows
- RSA key pair
- AES key

The adversary knows
- RSA public key
- a RSA-encrypted AES key
- an AES-encrypted WUP request

The adversary wants to know
- AES key

---

In this part, you are supposed to:
- Properly design your own WUP request format, server-client communication model, etc. 
- Generate a history message by yourself, it should includes a RSA-encrypted AES key and an AES-encrypted request.
- Present the attack process to obtain the AES key (and further decrypt the encrypted request) from the history message.

You can use third-party library to implement AES encryption and decryption.

---

Files to be Submitted and Standard of Grading:    
- Code : 10 points 
- CCA2 (Use RSA parameters in task 1):	 
    - History_Message.txt				1 point
    - AES_Key.txt (hexadecimal, 128bits) 		1 point
    - WUP_Request.txt (hexadecimal) 			1 point
    - AES_Encrypted_WUP.txt (hexadecimal) 		2 points
    - Attack Process to Obtain the AES key: 	10 points	
        - Both Screenshot and Log Files are OK



