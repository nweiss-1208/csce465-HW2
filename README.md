# CSCE 465 HW 2

This homework includes concepts such as:
- AES-CTR encryption
- Authenticated Diffie-Hellman handshake
- HMAC

## Environment Setup

From the HW2 directory, create and activate the Python environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required packages:
```bash
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

## Running the included tests:

From the directory, run the following:
```bash
python -m pytest -q
```

Expected result: "8 passed"
