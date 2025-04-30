from unittest import TestCase

from di_bip340.multikey import SchnorrSecp256k1Multikey
from di_bip340.cryptosuite import Bip340JcsCryptoSuite
from di_bip340.data_integrity_proof import DataIntegrityProof
import json

class DIProofVerify(TestCase):
    good_proofs = [
        {
            "secured_document": {
                "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1"
                    ],
                    "patch": [
                    {
                        "op": "add",
                        "path": "/service/1",
                        "value": {
                        "id": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp#service-1",
                        "type": "SingletonBeacon",
                        "serviceEndpoint": "bitcoin:bcrt1qser62ssp8n49yh5famt93m7tdgwqv76r3j9d5n"
                        }
                    },
                    {
                        "op": "add",
                        "path": "/verificationMethod/2",
                        "value": {
                        "id": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp#key-2",
                        "type": "Multikey",
                        "controller": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp",
                        "publicKeyMultibase": "zQ3shXtnYKjkm5a17b65bJ63TdqqP6cLMC6EEubVRvMtoR8DY"
                        }
                    }
                    ],
                    "sourceHash": "8Kpts1zHd1xxCEbXiL53phu8Xts9DUUnXHKvTHhM4m3u",
                    "targetHash": "8PjNUsm7aytqVC1BpcJE7WFmYobxRtqpsP4GPoLRW1s7",
                    "targetVersionId": 2,
                    "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "bip340-jcs-2025",
                    "verificationMethod": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp#key-1",
                    "proofPurpose": "capabilityInvocation",
                    "capability": "urn:zcap:root:did%3Abtc1%3Ax1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp",
                    "capabilityAction": "Write",
                    "@context": [
                        "https://w3id.org/security/v2",
                        "https://w3id.org/zcap/v1",
                        "https://w3id.org/json-ld-patch/v1"
                    ],
                    "proofValue": "z3SvqrVEjVur24zh1vnYHB3SxQPMvxXP1XMxjtqBptezKASXtUUTsotQh2rabGLDyBf8riJkcL9wbHkZjDRSYRVYC"
                }
            },
            "verification_method": {
                "id": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp#key-1",
                "type": "Multikey",
                "controller": "did:btc1:x1q20n602dgh7awm6akhgne0mjcmfpnjpc9jrqnrzuuexglrmklzm6u98hgvp",
                "publicKeyMultibase": "zQ3shNmrN4M1vcMtT57dfyYvVPhSVnzo8QUgcz4E5ZzJSzi4w"
            }
        },
        {
            "secured_document": {
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
                    "id": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#service-3",
                    "type": "SingletonBeacon",
                    "serviceEndpoint": "bitcoin:bcrt1qktf6vtfunylcgg62ltwj60k5rp4kr9h5y7kvyc"
                    }
                }
                ],
                "sourceHash": "5VyzaSL3x7ccqZD2DBUz6UqxHwSry72acuSBtd9qCeUh",
                "targetHash": "4D8WshMpQT5YLe4jL8KKfzAkobkwTSo3B9cuJn3acNoF",
                "targetVersionId": 2,
                "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "bip340-jcs-2025",
                "verificationMethod": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#initialKey",
                "proofPurpose": "capabilityInvocation",
                "capability": "urn:zcap:root:did%3Abtc1%3Ak1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack",
                "capabilityAction": "Write",
                "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1"
                ],
                "proofValue": "z257NSUxcuu4QhuQLviYgBWZJXZ5X2nN1vD9eVQKziFKah9cuiECQ8VQ7pQoxuLVCC8Aez8UziHv8JxTwPSWqFfKi"
                }
            },
            "verification_method": {
                "id": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#initialKey",
                "type": "Multikey",
                "controller": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack",
                "publicKeyMultibase": "zQ3shrDPUokmEsCT3Q9aRwzonncPLD6HBwSELReoUdHbgw19w"
            }
        },
        {
            "secured_document": {
                "@context": [
                "https://w3id.org/security/v2",
                "https://w3id.org/zcap/v1",
                "https://w3id.org/json-ld-patch/v1"
                ],
                "patch": [
                {
                    "op": "add",
                    "path": "/verificationMethod/1",
                    "value": {
                    "id": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#key-1",
                    "type": "Multikey",
                    "controller": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack",
                    "publicKeyMultibase": "zQ3shcZoWPNt46dp9o7iCSjMrXrFTkftKezEGJpZdQNzxfkn3"
                    }
                }
                ],
                "sourceHash": "4D8WshMpQT5YLe4jL8KKfzAkobkwTSo3B9cuJn3acNoF",
                "targetHash": "GWsfxFqgMJs29FakCXw7veGeUh1tE83GHGH4tyNLKdEA",
                "targetVersionId": 3,
                "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "bip340-jcs-2025",
                "verificationMethod": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#initialKey",
                "proofPurpose": "capabilityInvocation",
                "capability": "urn:zcap:root:did%3Abtc1%3Ak1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack",
                "capabilityAction": "Write",
                "@context": [
                    "https://w3id.org/security/v2",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/json-ld-patch/v1"
                ],
                "proofValue": "z2yCtyRxcMH6XDmGNtzNUNaQf6AGjm1nPQjUtYG6bf6A4mmac6dCSw3pZdpEZGYfdSHHndyTVpfAvqDkjsRpPHnuf"
                }
            },
            "verification_method": {
                "id": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack#initialKey",
                "type": "Multikey",
                "controller": "did:btc1:k1qgp6haekj3w5zgk56h92juynjl4ag4pt2p9wl4ajwu7yhklyp0ngcfskwzack",
                "publicKeyMultibase": "zQ3shrDPUokmEsCT3Q9aRwzonncPLD6HBwSELReoUdHbgw19w"
            }
        }
    ]

    def test_verify_proof(self):
        for test_case in self.good_proofs:
            vm = test_case["verification_method"]
            secured_document = test_case["secured_document"]
            multikey = SchnorrSecp256k1Multikey.from_verification_method(vm)

            cryptosuite = Bip340JcsCryptoSuite(multikey)
            di_proof = DataIntegrityProof(cryptosuite)

            verification_result = di_proof.verify_proof(None, json.dumps(secured_document), "capabilityInvocation", None, None)
            print(verification_result)
            self.assertTrue(verification_result)