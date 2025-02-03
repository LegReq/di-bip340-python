
import copy 
import jcs
from multiformats import multibase
from buidl.ecc import PrivateKey
from buidl.helper import sha256
# from secp

# Only considering the JCS cryptosuite
# Probably still want a base cryptosuite class
class CryptoSuite:
    type = "DataIntegrityProof"
    cryptosuite = "schnorr-secp256k1-jcs-2025"

    def __init__(self, type, cryptosuite):
        # TODO: this not quite right. Should be empty object.
        if CryptoSuite.type != type:
            raise "Not a DataIntegrityProof"
        
        if cryptosuite != CryptoSuite.cryptosuite:
            raise "Invalid Cryptosuite"
        
    def create_proof(self, unsecured_document, proof_options, signer):
        proof = copy.deepcopy(proof_options)
        proof_config = self.proof_configuration(proof_options)
        transformed_data = self.transform_document(unsecured_document,
                                                   proof_config, proof_options)
        hash_data = self.generate_hash(transformed_data, proof_config)

        proof_bytes = self.proof_serialization(hash_data, proof_options, signer)

        multibase_proof_bytes = multibase.encode(proof_bytes, "base58btc")

        proof["proofValue"] = multibase_proof_bytes

        return proof

    def verify_proof(self, secured_document):
        unsecured_document = copy.deepcopy(secured_document)
        del unsecured_document["proof"]
        proof_options = copy.deepcopy(secured_document["proof"])
        del proof_options["proofValue"]
        proof_bytes = multibase.decode(secured_document["proof"]["proofValue"])
        transformed_data = self.transform_document(unsecured_document,
                                                   proof_options)
        proof_config = self.transform_document(proof_options)
        hash_data = self.generate_hash(proof_config, transformed_data)
        
        verified = self.proof_verification(hash_data, proof_bytes,
                                           proof_options)
        
        verification_result = {"verified": verified}
        if verified:
            verification_result["verifiedDocument"] = unsecured_document
        else:
            verification_result["verifiedDocument"] = None
        
        return verification_result

    def transform_document(unsecured_document, options):
        if options["type"] != CryptoSuite.type and options["cryptosuite"] != CryptoSuite.cryptosuite:
            raise "PROOF VERIFICATION ERROR"
        
        canonical_document = jcs.canonicalize(unsecured_document)
        return canonical_document
        
    def generate_hash(self, canonical_proof_config, canonical_document):
        bytes_to_hash = canonical_proof_config + canonical_document
        hash_data = sha256(bytes_to_hash)
        return hash_data

    def proof_configuration(unsecured_document, options):
        proof_config = copy.deepcopy(options)

        if proof_config["type"] != CryptoSuite.type:
            raise "PROOF_GENERATION_ERROR"
        
        if proof_config["cryptosuite"] != CryptoSuite.cryptosuite:
            raise "PROOF_GENERATION_ERROR"
        
        if proof_config["created"]:
            # TODO: Check valid XMLSchema DateTime
            pass

        proof_config["@context"] = unsecured_document["@context"]
        canonical_proof_config = jcs.canonicalize(proof_config)
        return canonical_proof_config
    
    def proof_serialization(hash_data, proof_options, signer):
        # Check signer is for verificationmethod 
        # private_key_bytes = proof_options["verificationMethod"]

        proof_bytes = signer.sign(hash_data)
        return proof_bytes
        # proof_bytes = TODO: instantiate a signer and sign hash_dta

    def proof_verification(hash_data, proof_bytes, options):
        # TODO: retrieve publicKey from verificationMethod
        # See https://w3c.github.io/cid/#retrieve-verification-method
        # Verify proof bytes is a valid signature over hash_bytes 
        pass
        
