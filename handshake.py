import os

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

def load_dh_parameters():
	with open("ffdhe3072.pem", "rb") as file:
		return serialization.load_pem_parameters(file.read())

def generate_rsa_key():
	return rsa.generate_private_key(
		public_exponent=65537,
		key_size=3072,
	)

def generate_ephemeral_dh_key(parameters):
	return parameters.generate_private_key()

def generate_nonce():
	return os.urandom(16)

def encode_field(field):
	return len(field).to_bytes(4, "big") + field

def dh_public_bytes(public_key):
	y = public_key.public_numbers().y
	return y.to_bytes(384, "big")

def build_transcript(gateway_identity, node_identity, gateway_dh_public,
    node_dh_public, gateway_nonce, node_nonce):
	fields = [b"CSCE465-HS-v2",b"ffdhe3072",gateway_identity,
	    node_identity, dh_public_bytes(gateway_dh_public),
	    dh_public_bytes(node_dh_public), gateway_nonce, node_nonce]

	return b"".join(encode_field(field) for field in fields)

def parse_transcript(transcript, expected_fields=8):
	fields = []
	offset = 0

	for _ in range(expected_fields):
		if offset + 4 > len(transcript):
			raise ValueError("Malformed transcript length prefix")

		field_length = int.from_bytes(
		    transcript[offset:offset + 4],
		    "big"
		)
		offset += 4

		if offset + field_length > len(transcript):
			raise ValueError("Malformed transcript field length")

		fields.append(
		    transcript[offset:offset + field_length]
		)
		offset += field_length

	if offset != len(transcript):
		raise ValueError("Unexpected extra transcript data")

	return fields

def validate_transcript(transcript):
	fields = parse_transcript(transcript)

	if fields[0] != b"CSCE465-HS-v2":
		raise ValueError("Unexpected protocol label")

	if fields[1] != b"ffdhe3072":
		raise ValueError("Unexpected group indentifier")

	if len(fields[4]) != 384 or len(fields[5]) != 384:
		raise ValueError("Invalid DH public value length")

	if len(fields[6]) != 16 or len(fields[7]) != 16:
		raise ValueError("Invalid nonce length")

	return fields

def transcript_hash(transcript):
	validate_transcript(transcript)

	digest = hashes.Hash(hashes.SHA256())
	digest.update(transcript)
	return digest.finalize()

def sign_transcript(private_key, role, transcript):
	th = transcript_hash(transcript)
	message = role + th

	return private_key.sign(
	    message,
	    padding.PSS(
	        mgf=padding.MGF1(hashes.SHA256()),
	        salt_length=padding.PSS.MAX_LENGTH,
	    ),
	    hashes.SHA256(),
	)

def verify_transcript_signature(public_key, role, transcript, signature):
	th = transcript_hash(transcript)
	message = role + th

	public_key.verify(
	    signature,
	    message,
	    padding.PSS(
	        mgf=padding.MGF1(hashes.SHA256()),
	        salt_length=padding.PSS.MAX_LENGTH,
	    ),
	    hashes.SHA256(),
	)

def derive_shared_secret(private_key, peer_public_key):
	shared_secret = private_key.exchange(peer_public_key)

	z_int = int.from_bytes(shared_secret, "big")
	return z_int.to_bytes(384, "big")

def hmac_sha256(key, data):
	mac = hmac.HMAC(key, hashes.SHA256())
	mac.update(data)
	return mac.finalize()

def derive_session_keys(shared_secret, transcript):
	th = transcript_hash(transcript)

	digest = hashes.Hash(hashes.SHA256())
	digest.update(b"CSCE465-KDF-v1" + shared_secret + th)
	k_master = digest.finalize()

	k_g2n_enc = hmac_sha256(
	    k_master,
	    b"gateway-to-node encryption" + th,
	)

	k_g2n_mac = hmac_sha256(
	    k_master,
	    b"gateway-to-node MAC" + th,
	)

	k_n2g_enc = hmac_sha256(
	    k_master,
	    b"node-to-gateway encryption" + th,
	)

	k_n2g_mac = hmac_sha256(
	    k_master,
	    b"node-to-gateway MAC" + th,
	)

	session_id = hmac_sha256(
	    k_master,
	    b"session identifier" + th,
	)[:8]

	return (
	    k_g2n_enc,
	    k_g2n_mac,
	    k_n2g_enc,
	    k_n2g_mac,
	    session_id,
	)

def check_identities(
    transcript,
    expected_gateway_identity,
    expected_node_identity,
):
	fields = validate_transcript(transcript)

	if fields[2] != expected_gateway_identity:
		raise ValueError("Unexpected gateway identity")

	if fields[3] != expected_node_identity:
		raise ValueError("Unexpected node identity")

def run_handshake(
    gateway_rsa_key,
    node_rsa_key,
    gateway_identity=b"gateway",
    node_identity=b"node",
):
	parameters = load_dh_parameters()

	gateway_dh_private = generate_ephemeral_dh_key(parameters)
	node_dh_private = generate_ephemeral_dh_key(parameters)

	gateway_dh_public = gateway_dh_private.public_key()
	node_dh_public = node_dh_private.public_key()

	gateway_nonce = generate_nonce()
	node_nonce = generate_nonce()

	transcript = build_transcript(
	    gateway_identity,
	    node_identity,
	    gateway_dh_public,
	    node_dh_public,
	    gateway_nonce,
	    node_nonce,
	)

	check_identities(
	    transcript,
	    gateway_identity,
	    node_identity,
	)

	gateway_signature = sign_transcript(
	    gateway_rsa_key,
	    b"gateway",
	    transcript,
	)

	node_signature = sign_transcript(
	    node_rsa_key,
	    b"node",
	    transcript,
	)

	verify_transcript_signature(
	    gateway_rsa_key.public_key(),
	    b"gateway",
	    transcript,
	    gateway_signature,
	)

	verify_transcript_signature(
	    node_rsa_key.public_key(),
	    b"node",
	    transcript,
	    node_signature,
	)

	gateway_shared_secret = derive_shared_secret(
	    gateway_dh_private,
	    node_dh_public,
	)

	node_shared_secret = derive_shared_secret(
	    node_dh_private,
	    gateway_dh_public,
	)

	if gateway_shared_secret != node_shared_secret:
		raise ValueError("Diffie-Hellman shared secrets do not match")

	gateway_keys = derive_session_keys(
	    gateway_shared_secret,
	    transcript,
	)

	node_keys = derive_session_keys(
	    node_shared_secret,
	    transcript,
	)

	if gateway_keys != node_keys:
		raise ValueError("Derived session keys do not match")

	return gateway_keys

def main():
	gateway_rsa_key = generate_rsa_key()
	node_rsa_key = generate_rsa_key()

	session_keys = run_handshake(
	    gateway_rsa_key,
	    node_rsa_key,
	)

	print("Handshake successful")
	print("Session ID:", session_keys[4].hex())

if __name__ == "__main__":
	main()
