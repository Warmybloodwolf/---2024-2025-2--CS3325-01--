Goal: defend the attack
- Implement RSA-OAEP algorithm and discuss why it can defend such kind of attacks.

Since textbook RSA is vulnerable to attacks, in this paper, the authors give a solution: using OAEP key padding algorithm.

In cryptography, Optimal Asymmetric Encryption Padding (OAEP) is a padding scheme often used together with RSA encryption. OAEP satisfies the following two goals:
- Add an element of randomness which can be used to convert a deterministic encryption scheme (e.g., traditional RSA) into a probabilistic scheme.
- Prevent partial decryption of ciphertexts (or other information leakage) by ensuring that an adversary cannot recover any portion of the plaintext without being able to invert the trapdoor one-way permutation.

---

In this part, you are supposed to
- Add the OAEP padding module to the textbook RSA implementation.
- Give a discussion on the advantages of RSA-OAEP compared to the textbook RSA.
- Further try to present CCA2 attack to RSA-OAEP to see whether it can thwart the CCA2 attack you have implemented in part 2.

---

Files to be Submitted and Standard of Grading:    
- Code : 10 points 
- Encryption (Use RSA parameters and Message in task 1): 
    - Random_Number.txt			 1 point
    - Message_After_Padding.txt (hexadecimal) 1 point
    - Encrypted_Message.txt (hexadecimal)    	 1 point 
    - Pass Decryption (TA)                            	 2 points
	    - (Recommended using n=1024, k0=512, hash: sha512 )
- Any extra file added is OK but need to be explained in report!
