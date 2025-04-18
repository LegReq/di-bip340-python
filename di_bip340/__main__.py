from buidl.ecc import PrivateKey
import json
from multikey import SchnorrSecp256k1Multikey
from data_integrity_proof import DataIntegrityProof
from cryptosuite import Bip340JcsCryptoSuite

def main():
    secured_document = {
    "@context": [
      "https://w3id.org/security/v2",
      "https://w3id.org/zcap/v1",
      "https://w3id.org/json-ld-patch/v1"
    ],
    "patch": [
      {
        "op": "add",
        "path": "/service/3",
        "value": {
          "id": "#linked-domain",
          "type": "LinkedDomains",
          "serviceEndpoint": "https://contact-me.com"
        }
      }
    ],
    "sourceHash": "9kSA9j3z2X3a26yAdJi6nwg31qyfaHMCU1u81ZrkHirM",
    "targetHash": "C45TsdfkLZh5zL6pFfRmK93X4EdHusbCDwvt8d7Xs3dP",
    "targetVersionId": 2,
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "bip340-jcs-2025",
      "verificationMethod": "did:btc1:regtest:k1qdh2ef3aqne63sdhq8tr7c8zv9lyl5xy4llj8uw3ejfj5xsuhcacjq98ccc#initialKey",
      "proofPurpose": "capabilityInvocation",
      "capability": "urn:zcap:root:did%3Abtc1%3Aregtest%3Ak1qdh2ef3aqne63sdhq8tr7c8zv9lyl5xy4llj8uw3ejfj5xsuhcacjq98ccc",
      "capabilityAction": "Write",
      "@context": [
        "https://w3id.org/security/v2",
        "https://w3id.org/zcap/v1",
        "https://w3id.org/json-ld-patch/v1"
      ],
      "proofValue": "z3yfzVGdoDF4s8y4Bk8JeV9XuZw1nMeMtNW3x5brEm7DNtmWZkNBPbCLzUBJRpctBj9QJL1dydm94ZNsPxosPnkPP"
    }
    }

    vm = {
      "id": "#initialKey",
      "type": "Multikey",
      "controller": "did:btc1:regtest:k1qdh2ef3aqne63sdhq8tr7c8zv9lyl5xy4llj8uw3ejfj5xsuhcacjq98ccc",
      "publicKeyMultibase": "zQ3shn68faoXE2EqCTtefQXNLgaTa7ZohG2ftZjgXphStJsGc"
    }

    secret = 52464508790539176856770556715241483442035423615466097401201513777400180778402
    # private_key = PrivateKey(secret)

    multikey = SchnorrSecp256k1Multikey.from_verification_method(vm)

    cryptosuite = Bip340JcsCryptoSuite(multikey)
    di_proof = DataIntegrityProof(cryptosuite)
    
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "bip340-jcs-2025",
        "verificationMethod": multikey.full_id(),
        "proofPurpose": "capabilityInvocation"
    }


    # secured_document = di_proof.add_proof(unsecured_document, options)

    # print(json.dumps(secured_document, indent=4))

    # di_proof.add_proof(unsecured_document, )

    verification_result = di_proof.verify_proof(None, json.dumps(secured_document), "capabilityInvocation", None, None)
    print(verification_result)
    


if __name__ == "__main__":
    main()