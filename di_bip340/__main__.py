from buidl.ecc import PrivateKey
import json
from di_bip340.multikey import SchnorrSecp256k1Multikey
from data_integrity_proof import DataIntegrityProof
from cryptosuite import Bip340JcsCryptoSuite

def main():
    unsecured_document = {
        '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'],
        'id': 'http://university.example/credentials/58473',
        'type': ['VerifiableCredential', 'ExampleAlumniCredential'],
        'validFrom': '2020-01-01T00:00:00Z',
        'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
            'alumniOf': {
                'id': 'did:example:c276e12ec21ebfeb1f712ebc6f1',
                'name': 'Example University'
            }
        },
        'issuer': 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65'}
    
    secret = 52464508790539176856770556715241483442035423615466097401201513777400180778402
    private_key = PrivateKey(secret)

    multikey = SchnorrSecp256k1Multikey(id="#initialKey", 
                                      controller="did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65", 
                                      private_key=private_key)

    cryptosuite = Bip340JcsCryptoSuite(multikey)
    di_proof = DataIntegrityProof(cryptosuite)
    
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "bip340-jcs-2025",
        "verificationMethod": "did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65#initialKey",
        "proofPurpose": "attestationMethod"

    }


    secured_document = di_proof.add_proof(unsecured_document, options)

    print(json.dumps(secured_document, indent=4))

    # di_proof.add_proof(unsecured_document, )

    verification_result = di_proof.verify_proof(None, json.dumps(secured_document), "attestationMethod", None, None)
    print(verification_result)
    


if __name__ == "__main__":
    main()