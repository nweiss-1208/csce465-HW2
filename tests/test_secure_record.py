import pytest

from handshake import generate_rsa_key, run_handshake
from secure_record import (DIRECTION_G2N, DIRECTION_N2G, RecordLayer)

def make_record_layers():
	gateway_rsa_key = generate_rsa_key()
	node_rsa_key = generate_rsa_key()

	(
	    k_g2n_enc,
	    k_g2n_mac,
	    k_n2g_enc,
	    k_n2g_mac,
	    session_id,
	) = run_handshake(
	    gateway_rsa_key,
	    node_rsa_key,
	)

	gateway = RecordLayer(
	    k_g2n_enc,
	    k_g2n_mac,
	    k_n2g_enc,
	    k_n2g_mac,
	    session_id,
	    DIRECTION_G2N,
	    DIRECTION_N2G,
	)

	node = RecordLayer(
	    k_n2g_enc,
	    k_n2g_mac,
	    k_g2n_enc,
	    k_g2n_mac,
	    session_id,
	    DIRECTION_N2G,
	    DIRECTION_G2N,
	)

	return gateway, node

def test_valid_bidirectional_messages():
	gateway, node = make_record_layers()

	gateway_record = gateway.seal(
	    1,
	    b"Hello from gateway",
	)

	message_type, plaintext = node.open(gateway_record)

	assert message_type == 1
	assert plaintext == b"Hello from gateway"

	node_record = node.seal(
	    1,
	    b"Hello from node",
	)

	message_type, plaintext = gateway.open(node_record)

	assert message_type == 1
	assert plaintext == b"Hello from node"

def test_modified_ciphertext_rejected():
	gateway, node = make_record_layers()

	record = gateway.seal(
	    1,
	    b"Hello from gateway",
	)

	modified = bytearray(record)

	ciphertext_start = 15 + 16
	modified[ciphertext_start] ^= 0x01

	with pytest.raises(ValueError, match="Invalid authentication tag"):
		node.open(bytes(modified))

def test_modified_header_rejected():
	gateway, node = make_record_layers()

	record = gateway.seal(
	    1,
	    b"Hello from gateway",
	)

	modified = bytearray(record)

	modified[10] ^= 0x01

	with pytest.raises(ValueError, match="Invalid authentication tag"):
		node.open(bytes(modified))

def test_replayed_record_rejected():
	gateway, node = make_record_layers()

	record = gateway.seal(
	    1,
	    b"Hello from gateway",
	)

	node.open(record)

	with pytest.raises(ValueError, match="Unexpected sequence number"):
		node.open(record)

def test_reflected_record_rejected():
	gateway, node = make_record_layers()

	record = gateway.seal(
	    1,
	    b"Hello from gateway",
	)

	with pytest.raises(ValueError, match="Wrong direction"):
		gateway.open(record)

