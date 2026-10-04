from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1

DIRECTION_G2N = 0
DIRECTION_N2G = 1

def build_header(version, direction, sequence, message_type, ciphertext_length):
	return (
	    version.to_bytes(1, "big") + direction.to_bytes(1, "big")
	    + sequence.to_bytes(8, "big") + message_type.to_bytes(1, "big")
	    + ciphertext_length.to_bytes(4, "big")
	)

def build_iv(session_id, sequence):
	if len(session_id) != 8:
		raise ValueError("Session ID must be 8 bytes")

	return session_id + sequence.to_bytes(8, "big")

def encrypt_ctr(key, iv, plaintext):
	cipher = Cipher(
	    algorithms.AES(key),
	    modes.CTR(iv),
	)
	encryptor = cipher.encryptor()
	return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ctr(key, iv, ciphertext):
	cipher = Cipher(
	    algorithms.AES(key),
	    modes.CTR(iv),
	)
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def compute_tag(key, data):
	mac = hmac.HMAC(key, hashes.SHA256())
	mac.update(data)
	return mac.finalize()

def seal(k_enc, k_mac, session_id, direction, sequence, message_type, plaintext):
	iv = build_iv(session_id, sequence)

	ciphertext = encrypt_ctr(k_enc, iv, plaintext)

	header = build_header(
	    VERSION,
	    direction,
	    sequence,
	    message_type,
	    len(ciphertext),
	)

	tag = compute_tag(k_mac, header + iv + ciphertext)

	return header + iv + ciphertext + tag

def open_record(
    k_enc,
    k_mac,
    session_id,
    expected_direction,
    expected_sequence,
    record,
):
	header_length = 15
	iv_length = 16
	tag_length = 32

	if len(record) < header_length + iv_length + tag_length:
		raise ValueError("Record is too short")

	header = record[:header_length]

	version = header[0]
	direction = header[1]
	sequence = int.from_bytes(header[2:10], "big")
	message_type = header[10]
	ciphertext_length = int.from_bytes(header[11:15], "big")

	if version != VERSION:
		raise ValueError("Unexpected version")

	if direction != expected_direction:
		raise ValueError("Wrong direction")

	if sequence != expected_sequence:
		raise ValueError("Unexpected sequence number")

	expected_record_length = (header_length + iv_length
	    + ciphertext_length + tag_length)

	if len(record) != expected_record_length:
		raise ValueError("Invalid ciphertext length")

	iv_start = header_length
	iv_end = iv_start + iv_length

	ciphertext_start = iv_end
	ciphertext_end = ciphertext_start + ciphertext_length

	iv = record[iv_start:iv_end]
	ciphertext = record[ciphertext_start:ciphertext_end]
	tag = record[ciphertext_end:]

	expected_iv = build_iv(session_id, sequence)

	if iv != expected_iv:
		raise ValueError("Invalid IV")

	mac = hmac.HMAC(k_mac, hashes.SHA256())
	mac.update(header + iv + ciphertext)

	try:
		mac.verify(tag)
	except InvalidSignature:
		raise ValueError("Invalid authentication tag")

	plaintext = decrypt_ctr(k_enc, iv, ciphertext)

	return message_type, plaintext

class RecordLayer:
	def __init__(
	    self,
	    send_enc_key,
	    send_mac_key,
	    recv_enc_key,
	    recv_mac_key,
	    session_id,
	    send_direction,
	    recv_direction,
	):
		self.send_enc_key = send_enc_key
		self.send_mac_key = send_mac_key
		self.recv_enc_key = recv_enc_key
		self.recv_mac_key = recv_mac_key
		self.session_id = session_id

		self.send_direction = send_direction
		self.recv_direction = recv_direction

		self.send_sequence = 0
		self.recv_sequence = 0

	def seal(self, message_type, plaintext):
		record = seal(
		    self.send_enc_key,
		    self.send_mac_key,
		    self.session_id,
		    self.send_direction,
		    self.send_sequence,
		    message_type,
		    plaintext,
		)

		self.send_sequence += 1
		return record

	def open(self, record):
		message_type, plaintext = open_record(
		    self.recv_enc_key,
		    self.recv_mac_key,
		    self.session_id,
		    self.recv_direction,
		    self.recv_sequence,
		    record,
		)

		self.recv_sequence += 1
		return message_type, plaintext

