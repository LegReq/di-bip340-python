import copy
import json

class DataIntegrityProof:

    def __init__(self, cryptosuite):
        self.cryptosuite = cryptosuite

    def add_proof(self, input_document, options):

        proof = self.cryptosuite.create_proof(input_document, options)

        type = proof.get("type")
        vm = proof["verificationMethod"]
        proof_purpose = proof["proofPurpose"]
        if not type or not vm or not proof_purpose:
            raise "PROOF_GENERATION_ERROR"
        
        domain = options.get("domain")
        # TODO: Make proof domain a list
        proof_domain = proof.get("domain")

        if domain and domain != proof_domain:
            raise "PROOF_GENERATION_ERROR"
        
        challenge = options.get("challenge")
        if challenge and challenge != proof["challenge"]:
            raise "PROOF_GENERATION_ERROR"
        
        secured_document = copy.deepcopy(input_document)
        secured_document["proof"] = proof
        return secured_document

    def verify_proof(self, media_type, document_bytes, expected_proof_purpose, domain, challenge):
        
        # try:
            # doc_str = document_bytes.decode("utf-8")
            # TODO: Test this works
        secured_document = json.loads(document_bytes)

        if not isinstance(secured_document, dict) or not isinstance(secured_document["proof"], dict):
            # TODO: Catch and handle errors
            raise "PARSING_ERROR"
        
        proof = secured_document["proof"]

        type = proof.get("type")
        proof_purpose = proof.get("proofPurpose")
        proof_vm = proof.get("verificationMethod")
        proof_challenge = proof.get("challenge")
        
        if not type or not proof_vm or not proof_purpose:
            raise "PROOF_VERIFICATION_ERROR"
        
        if expected_proof_purpose and expected_proof_purpose != proof_purpose:
            print(proof_purpose, expected_proof_purpose)
            raise "PROOF_VERIFICATION_ERROR"

        # If domain was given, and it does not contain the same strings
        # as proof.domain (treating a single string as a set containing 
        # just that string), an error MUST be raised and SHOULD convey an error type of INVALID_DOMAIN_ERROR.
        # TODO: handle better. Domain is a list. Where proof domain not always a list.

        # if domain and domain != proof["domain"]:
        #     raise 
            
        if challenge and challenge != proof_challenge:
            raise "INVALID_CHALLENGE_ERROR"
        
        cryptosuite_verification_result = self.cryptosuite.verify_proof(secured_document)
        
        verification_result = {
            "verified": cryptosuite_verification_result["verified"],
            "verifiedDocument": cryptosuite_verification_result["verifiedDocument"],
            "mediaType": media_type
        }

        return verification_result
        
        # except Exception:

        #     # TODO: need to catch the different errors
        #     print("Handle errors")

        

