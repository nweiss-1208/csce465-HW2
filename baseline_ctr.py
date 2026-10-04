import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ORIGINAL = b'{"action":"READ","path":"notes.txt"}'
MODIFIED_ACTION = b"SEND"

def encrypt_ctr(key, iv, plaintext):
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
	encryptor = cipher.encryptor()
	return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ctr(key, iv, ciphertext):
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def relay_modify(ciphertext):
	modified = bytearray(ciphertext)

	start = ORIGINAL.index(b"READ")

	original_bytes = b"READ"
	new_bytes = MODIFIED_ACTION

	xor_mask = bytes(
		original ^ new
		for original, new in zip(original_bytes, new_bytes)
	)

	for i in range (len(xor_mask)):
		modified[start + i] ^= xor_mask[i]

	print("Original bytes:", original_bytes)
	print("Modified bytes:", new_bytes)
	print("XOR mask:", xor_mask.hex())

	return bytes(modified)

def receiver(key, iv, ciphertext):
	plaintext = decrypt_ctr(key, iv, ciphertext)
	print("Receiver processed:", plaintext)

def main():
	key = os.urandom(32)
	iv = os.urandom(16)

	ciphertext = encrypt_ctr(key, iv, ORIGINAL)

	print("Original plaintext:", ORIGINAL)
	print("Original ciphertext:", ciphertext.hex())
	print()

	modified_ciphertext = relay_modify(ciphertext)

	print("Modified ciphertext:", modified_ciphertext.hex())
	print()

	print("--- Modified Message ---")
	receiver(key, iv, modified_ciphertext)
	print()

	print("--- Replay Demonstration ---")
	receiver(key, iv, ciphertext)
	receiver(key, iv, ciphertext)

if __name__ == "__main__":
	main()
