from __future__ import unicode_literals


from shamir_id_sig.lib.asn1crypto_idb_custom.csr_structures import *
import shamir_id_sig.lib.id_signatures as Signatures
from Crypto.Hash import SHA256
from OpenSSL import crypto
import pickle

def create_key_pair(key_type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    if key_type == 'rsa':
        public_key, private_key = asymmetric.generate_pair(key_type, bits)
    return public_key, private_key


def create_csr_idb(priv_key_id, pub_key_id, pub_key_rsa, org_name, cname, country_name='PL'):
    
    builder = IDBCSRBuilder(
        {
            'country_name': country_name,
            'organization_name': org_name,
            'common_name': cname,
        },
        pub_key_rsa, 
    )
    request = builder.build(priv_key_id, pub_key_id)
    return request

def create_csr_rsa(pub_key, priv_key, digest="sha1", **name):
    """
    Create a certificate request.
    Arguments:  pub_key   - The key to associate with the request
                priv_key - The private key to sign the request
                digest - Digestion method to use for signing, default is md5
                **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pub_key)
    req.sign(priv_key, digest)
    return req