from buidl.ecc import PrivateKey, SchnorrSignature, S256Point
import os
from multiformats import varint, multibase

SECP256K1_XONLY_PUBLIC_KEY_PREFIX = varint.encode(0x2561)


class SchnorrSecp256k1Multikey:

    def __init__(self, id, controller, private_key: PrivateKey = None,
                 public_key: S256Point = None):
        self.id = id
        self.controller = controller
        if private_key:
            self.private_key = private_key
            self.public_key = private_key.point
        elif public_key:
            self.public_key = public_key
        else:
            raise "Must pass public or private key"

    def sign(self, hash_data):
        if not self.private_key:
            raise "Not a signer"
        aux = os.urandom(32)
        sig = self.private_key.sign_schnorr(hash_data, aux)
        sig_bytes = sig.serialize()
        return sig_bytes
    
    def full_id(self):
        if self.id[0] == "#":
            return f"{self.controller}{self.id}"
        
        return self.id

    def verify(self, hash_data, sig_bytes):
        sig = SchnorrSignature.parse(sig_bytes)
        print(sig)
        verified = self.public_key.verify_schnorr(hash_data, sig)
        print(verified)
        return verified
        

    def to_verification_method(self):
        verification_method = {}
        verification_method["id"] = self.id
        verification_method["type"] = "Multikey"
        verification_method["controller"] = self.controller

        xonly_key_bytes = self.public_key.xonly()
        multikey_bytes = SECP256K1_XONLY_PUBLIC_KEY_PREFIX + xonly_key_bytes
        pubkey_multibase = multibase.encode(multikey_bytes, "base58btc")

        verification_method["publicKeyMultibase"] = pubkey_multibase

        return verification_method


    def from_verification_method(verification_method):
        id = verification_method.get("id")
        type = verification_method.get("type")
        controller = verification_method.get("controller")
        pubkey_multibase = verification_method.get("publicKeyMultibase")

        if not id:
            raise Exception("verificationMethod has no id field")
        
        if not type or type != "Multikey":
            raise Exception("Incorrect verificationMethod type, expecting Multikey : ", type)
        
        if not controller:
            raise Exception("verificationMethod has no controller property set")
        
        if not pubkey_multibase:
            raise Exception("verificationMethod has no publicKeyMultibase")
        
        multikey_value = multibase.decode(pubkey_multibase)

        prefix = multikey_value[:2]
        if prefix != SECP256K1_XONLY_PUBLIC_KEY_PREFIX:
            raise Exception("Unexpected multikey type")
        
        key_bytes = multikey_value[2:]

        public_key = S256Point.parse_xonly(key_bytes)

        return SchnorrSecp256k1Multikey(id, controller, public_key=public_key)

        
