# Data Integrity using the [BIP340 CryptoSuite](https://dcdpr.github.io/data-integrity-schnorr-secp256k1/)
## Experimental Python Implementation

> Warning: This code is for experimental purposes only and should NOT be used in production.



## Prerequisites

- Python >= 3.8
- Pip


## Getting started

1. Create a virtual environment

`python -m venv venv`

2. Activate the virtual environment

`source venv/bin/activate`

3. Install the package requirements

`pip install -e .`

4. Run the main (See `di_bip340/__main__.py`)

`python di_bip340`

The code in `__main__.py`, creates and verifies a DateIntegrityProof on a Verifiable Credential using the `bip340-jcs-2025` CryptoSuite.

## Relevant Specifications

- https://dcdpr.github.io/data-integrity-schnorr-secp256k1/
- https://w3c.github.io/vc-data-integrity/