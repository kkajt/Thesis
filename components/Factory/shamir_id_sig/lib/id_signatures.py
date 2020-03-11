from Crypto.PublicKey import RSA 
from Cryptodome.Hash import SHA3_256, SHAKE256
import random

def verify(s, i, t, m, n, e=65537, id_ext_len=256, f_out_len=256):
    '''
    Verification of the signature 

    Args:
        m: message
        s, t: signature
        i: user identity
        n: product of two large primes
        e: large prime relatively prime to phi(n)
        f: one way function
    
    Returns: 
        bool: True if sign matches message, false otherwise
    '''
    return pow(s, e, n) == expand_identity(i, n = id_ext_len) * pow(t,f(t,m, out_len=f_out_len), n) % n

def sign(g, m, n, e):
    '''
    Sign message with device private key

    Args:
        g: private ID-based key
        m: message to sign
        n, e: parts of ID-based public key

    Returns:
        tuple: (s, t) - signature of the message m
    '''
    r = get_random_num()
    t = pow(r, e, n)
    s = g * pow(r, f(t, m), n) % n
    return s, t

def gcd(a, b):
    if (b == 0):
        return a
    else:
        return gcd(b, a % b)

def ext_gcd(a, b):
    x, old_x = 0, 1
    y, old_y = 1, 0

    while (b != 0):
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return a, old_x, old_y

def get_random_num(bits=128):
    '''
    Chosen random number generator

    Args:
        bits: length of random number in bits

    Returns:
        int: random integer of bit length 'bits'
    '''
    return random.getrandbits(bits)


def expand_identity(i, n=256):
    '''
    Function to expand identity to number in Z_n for better security results

    Args:
        i: string, user identity
        n: size of output length in bits
    
    Returns:
        int: SHAKE256 hash value of given identity 
    '''
    h_obj = SHAKE256.new()
    h_obj.update(i.encode('utf-8'))
    return int.from_bytes(h_obj.read(n), byteorder="little")

def initialise_CA_key_pair(e):
    '''
    return p, q
    '''
    priv_key, pub_key = generate_RSA_key_pair(e=e)
    return priv_key, pub_key

def f(t, m, out_len=256):
    '''
    A one way function for ID-based signature scheme

    Args:
        m: string, message 
        t: part of the signature
        out_len: size of output in bits
    
    Returns:
        int: SHAKE256 hash value of t and m
    '''
    if isinstance(t, str):
        t = t.encode('utf-8')
    if isinstance(m, str):
        m = m.encode('utf-8')
    h_obj = SHAKE256.new()
    h_obj.update(t.to_bytes(256, byteorder="little"))
    h_obj.update(m)
    return int.from_bytes(h_obj.read(out_len), byteorder="little")

def generate_RSA_key_pair(bits=2048, e=65537):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format

    Args:
        bits: the key length in bits
        e: part of the public key
    
    Returns:
        tuple: private key and public key
    '''
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey() 
    private_key = new_key 
    
    return private_key, public_key

def write_key_to_file(filename, key):
    '''
    Write key to file in PEM format
    '''
    with open(filename, 'wb') as f:
        f.write(key.exportKey("PEM"))

def read_key_from_file(filename):
    '''
    Read data from file in PEM format
    '''
    with open(filename, 'rb') as f:
        key = f.read()
        return RSA.importKey(key)

def get_device_public_key(i, m_pub_key):
    '''
    Derive device public key 

    Args:
        i: user's identity
        m_pub_key: ID-based master public key

    Returns:
        tuple: all three parts of user's public key

    '''
    return expand_identity(i), m_pub_key.n, m_pub_key.e


def get_device_private_key(key, i):
    '''
    Gets user private key. Uses RSA functions.

    Args:
        key: ID-based master private key
        i: user identity

    Returns:
        tuple: device private key
    '''
    g = key.decrypt(expand_identity(i))
    return g, key.n
