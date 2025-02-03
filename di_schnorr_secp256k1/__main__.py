from buidl.ecc import PrivateKey




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

    def sign(hash_data):
        aux = b"\x00" * 32
        sig = private_key.sign_schnorr(hash_data, aux)
        return sig
    
    # TODO: need to define a SecpSchnorrMultikey class.
    # signer = 

    print("Hello World!")


if __name__ == "__main__":
    main()