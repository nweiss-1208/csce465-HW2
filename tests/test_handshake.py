import pytest

from cryptography.exceptions import InvalidSignature

from handshake import (build_transcript, generate_ephemeral_dh_key,
    generate_nonce, generate_rsa_key, load_dh_parameters,
    run_handshake, sign_transcript, verify_transcript_signature)

def test_valid_handshake():
	gateway_rsa_key = generate_rsa_key()
	node_rsa_key = generate_rsa_key()

	session_keys = run_handshake(gateway_rsa_key, node_rsa_key)

	assert len(session_keys) == 5
	assert len(session_keys[4]) == 8

def test_reflected_handshake_rejected():
	gateway_rsa_key = generate_rsa_key()
	parameters = load_dh_parameters()

	gateway_dh_private = generate_ephemeral_dh_key(parameters)
	node_dh_private = generate_ephemeral_dh_key(parameters)

	transcript = build_transcript(
	    b"gateway",
	    b"node",
	    gateway_dh_private.public_key(),
	    node_dh_private.public_key(),
	    generate_nonce(),
	    generate_nonce(),
	)

	gateway_signature = sign_transcript(
	    gateway_rsa_key,
	    b"gateway",
	    transcript,
	)

	with pytest.raises(InvalidSignature):
		verify_transcript_signature(
		    gateway_rsa_key.public_key(),
		    b"node",
		    transcript,
		    gateway_signature,
		)

def test_incorrect_rsa_public_key_rejected():
	gateway_rsa_key = generate_rsa_key()
	wrong_rsa_key = generate_rsa_key()
	parameters = load_dh_parameters()

	gateway_dh_private = generate_ephemeral_dh_key(parameters)
	node_dh_private = generate_ephemeral_dh_key(parameters)

	transcript = build_transcript(
	    b"gateway",
	    b"node",
	    gateway_dh_private.public_key(),
	    node_dh_private.public_key(),
	    generate_nonce(),
	    generate_nonce(),
	)

	gateway_signature = sign_transcript(
	    gateway_rsa_key,
	    b"gateway",
	    transcript,
	)

	with pytest.raises(InvalidSignature):
		verify_transcript_signature(
		    wrong_rsa_key.public_key(),
		    b"gateway",
		    transcript,
		    gateway_signature,
		)
