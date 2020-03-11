from asn1crypto.algos import *
from asn1crypto.csr import *
from csrbuilder import *
import pickle
from Crypto.Hash import SHA256
import shamir_id_sig.lib.id_signatures as Signatures

class IDBSignedDigestAlgorithmId(SignedDigestAlgorithmId):
    _map = {
        '1.3.14.3.2.3': 'md5_rsa',
        '1.3.14.3.2.29': 'sha1_rsa',
        '1.3.14.7.2.3.1': 'md2_rsa',
        '1.2.840.113549.1.1.2': 'md2_rsa',
        '1.2.840.113549.1.1.4': 'md5_rsa',
        '1.2.840.113549.1.1.5': 'sha1_rsa',
        '1.2.840.113549.1.1.14': 'sha224_rsa',
        '1.2.840.113549.1.1.11': 'sha256_rsa',
        '1.2.840.113549.1.1.12': 'sha384_rsa',
        '1.2.840.113549.1.1.13': 'sha512_rsa',
        '1.2.840.113549.1.1.10': 'rsassa_pss',
        '1.2.840.10040.4.3': 'sha1_dsa',
        '1.3.14.3.2.13': 'sha1_dsa',
        '1.3.14.3.2.27': 'sha1_dsa',
        '2.16.840.1.101.3.4.3.1': 'sha224_dsa',
        '2.16.840.1.101.3.4.3.2': 'sha256_dsa',
        '1.2.840.10045.4.1': 'sha1_ecdsa',
        '1.2.840.10045.4.3.1': 'sha224_ecdsa',
        '1.2.840.10045.4.3.2': 'sha256_ecdsa',
        '1.2.840.10045.4.3.3': 'sha384_ecdsa',
        '1.2.840.10045.4.3.4': 'sha512_ecdsa',
        '2.16.840.1.101.3.4.3.9': 'sha3_224_ecdsa',
        '2.16.840.1.101.3.4.3.10': 'sha3_256_ecdsa',
        '2.16.840.1.101.3.4.3.11': 'sha3_384_ecdsa',
        '2.16.840.1.101.3.4.3.12': 'sha3_512_ecdsa',
        # For when the digest is specified elsewhere in a Sequence
        '1.2.840.113549.1.1.1': 'rsassa_pkcs1v15',
        '1.2.840.10040.4.1': 'dsa',
        '1.2.840.10045.4': 'ecdsa',
        '1.1.1.1.1.1.1.1.1': 'sha256_idb',
    }
    
    _reverse_map = {
        'dsa': '1.2.840.10040.4.1',
        'ecdsa': '1.2.840.10045.4',
        'md2_rsa': '1.2.840.113549.1.1.2',
        'md5_rsa': '1.2.840.113549.1.1.4',
        'rsassa_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsassa_pss': '1.2.840.113549.1.1.10',
        'sha1_dsa': '1.2.840.10040.4.3',
        'sha1_ecdsa': '1.2.840.10045.4.1',
        'sha1_rsa': '1.2.840.113549.1.1.5',
        'sha224_dsa': '2.16.840.1.101.3.4.3.1',
        'sha224_ecdsa': '1.2.840.10045.4.3.1',
        'sha224_rsa': '1.2.840.113549.1.1.14',
        'sha256_dsa': '2.16.840.1.101.3.4.3.2',
        'sha256_ecdsa': '1.2.840.10045.4.3.2',
        'sha256_rsa': '1.2.840.113549.1.1.11',
        'sha384_ecdsa': '1.2.840.10045.4.3.3',
        'sha384_rsa': '1.2.840.113549.1.1.12',
        'sha512_ecdsa': '1.2.840.10045.4.3.4',
        'sha512_rsa': '1.2.840.113549.1.1.13',
        'sha3_224_ecdsa': '2.16.840.1.101.3.4.3.9',
        'sha3_256_ecdsa': '2.16.840.1.101.3.4.3.10',
        'sha3_384_ecdsa': '2.16.840.1.101.3.4.3.11',
        'sha3_512_ecdsa': '2.16.840.1.101.3.4.3.12',
        'sha256_idb': '1.1.1.1.1.1.1.1.1',
    }

class IDBMaskGenAlgorithmId(ObjectIdentifier):
    _map = {
        '2.16.840.1.101.3.4.2.12': 'shake256',
    }

class IDBMaskGenAlgorithm(Sequence):
    _fields = [
        ('algorithm', IDBMaskGenAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'shake256': DigestAlgorithm
    }

class IDBParams(Sequence):
    _fields = [
        (
            'mask_gen_algorithm',
            IDBMaskGenAlgorithm,
            {
                'default': {
                    'algorithm': 'shake256',
                    'parameters': {'algorithm': 'sha1'},
                },
            }
        ),
        (
            'ext_id_length',
            Integer,
            {
                'default': 256,
            }
        ),
        (
            'f_output_length',
            Integer,
            {
                'default': 256,
            }
        ),
    ]

class IDBSignedDigestAlgorithm(SignedDigestAlgorithm):
    _fields = [
        ('algorithm', IDBSignedDigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsassa_pss': RSASSAPSSParams,
        'sha256_idb': IDBParams
    }

    @property
    def signature_algo(self):
        algorithm = self['algorithm'].native
        if algorithm == 'sha256_idb':
            return 'idb'
        else:
            return super().signature_algo()

    @property
    def hash_algo(self):
        algorithm = self['algorithm'].native
        if algorithm == 'sha256_idb':
            return 'sha256'
        else:
            return super().hash_algo()

class IDBCertificationRequest(CertificationRequest):
    _fields = [
        ('certification_request_info', CertificationRequestInfo),
        ('signature_algorithm', IDBSignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]

class IDBCSRBuilder(CSRBuilder):
    def build(self, signing_private_key, pub_key):
        signature_algo = 'idb'
        hash_algo = 'sha256'
        signature_algorithm_id = '%s_%s' % (hash_algo, signature_algo)

        attributes = []

        certification_request_info = csr.CertificationRequestInfo({
            'version': 'v1',
            'subject': self._subject,
            'subject_pk_info': self._subject_public_key,
            'attributes': attributes
        })
        signature = id_sign(signing_private_key, pub_key, certification_request_info.dump(), hash_algo)

        return IDBCertificationRequest({
            'certification_request_info': certification_request_info,
            'signature_algorithm': {
                'algorithm': signature_algorithm_id,
                'parameters': {
                    'mask_gen_algorithm': {'algorithm': 'shake256'},
                    'ext_id_length': 256,
                    'f_output_length': 256,
                },
            },
            'signature': signature
        })

def id_sign(priv_key, pub_key, data, hash_algo):
    h = SHA256.new()   
    h.update(data)
    s, t = Signatures.sign(priv_key[0], h.hexdigest(), pub_key[1], pub_key[2])
    return pickle.dumps((s, t))