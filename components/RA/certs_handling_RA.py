from cryptography.hazmat.primitives import hashes
from cryptography import x509
from oscrypto import asymmetric

"""
Certificate generation module.
"""

from OpenSSL import crypto
import pickle
from shamir_id_sig.lib.id_signatures import verify 
from Crypto.Hash import SHA256
from shamir_id_sig.lib.asn1crypto_idb_custom.csr_structures import *

def createCertificate(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="sha1", terminal=False):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """

    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

def verify_csr_terminal(req):
    return req.verify(req.get_pubkey())

def verify_csr_sensor(req, factory_pub_key):
    sig_alg = req['signature_algorithm']['algorithm'].native
    if (sig_alg != 'sha256_idb' and sig_alg != 'sha1_rsa'):
        raise ValueError("Wrong signature algorithm type. Exptected: sha256_idb (1.1.1.1.1.1) or sha1_rsa, found: %s" % sig_alg)
    sign_val = req['signature'].native
    name = req['certification_request_info']
    hashed = sha256_val(name)
    if sig_alg == 'sha256_idb':
        signature = pickle.loads(sign_val)
        if not isinstance(signature, tuple):
            raise TypeError("Unknown format of signature.")
        device_id = req['certification_request_info']['subject'].native['common_name']

        mask_gen_alg = req['signature_algorithm']['parameters']['mask_gen_algorithm']['algorithm'].native
        ext_id_length = req['signature_algorithm']['parameters']['ext_id_length'].native
        f_output_length = req['signature_algorithm']['parameters']['f_output_length'].native

        if mask_gen_alg != 'shake256':
            print("Unknown mask generation algorithm. Aborting...")
            return False
        return verify(signature[0], device_id, signature[1], bytes(hashed, 'UTF-8'), 
            factory_pub_key.n, factory_pub_key.e, id_ext_len=ext_id_length, f_out_len=f_output_length)
    else:
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, pem_armor_csr(req))
        return req.verify(req.get_pubkey())

def sha256_val(val):
    h = SHA256.new()   
    h.update(val.dump())
    return h.hexdigest()
    
