import unittest

from ..lib.ID_CA import ID_CA
from shamir_id_sig.lib.Device import Device
from shamir_id_sig.lib.id_signatures import verify

class TestSignature(unittest.TestCase):
    test_pub_key_file = "./keys/test_pub.txt"
    test_priv_key_file = "./keys/test_priv.txt"

    def setUp(self):
        self.CA = ID_CA()
        self.CA.import_keys_from_files(self.test_pub_key_file, self.test_priv_key_file)

    def test_signature_passes(self):
        device_id = "abcdefghijklmnoprstuvwxyz"
        my_device = Device(device_id)
        my_device.pub_key, my_device.priv_key = self.CA.generate_keys_for_id(device_id)
        sign_msg = b'Testing'
        s, t = my_device.sign(sign_msg)
        self.assertTrue(verify(s, device_id, t, sign_msg, self.CA.pub_key.n))

    def test_signature_fails_on_other_msg(self):
        device_id = "abcdefghijklmnoprstuvwxyz"
        my_device = Device(device_id)
        my_device.pub_key, my_device.priv_key = self.CA.generate_keys_for_id(device_id)
        sign_msg = b'Testing'
        sign_msg2 = b'Testing2'
        s, t = my_device.sign(sign_msg)
        self.assertTrue(verify(s, device_id, t, sign_msg, self.CA.pub_key.n))
        self.assertFalse(verify(s, device_id, t, sign_msg2, self.CA.pub_key.n))
    
    def test_signature_fails_on_case_difference(self):
        device_id = "abcdefghijklmnoprstuvwxyz"
        my_device = Device(device_id)
        my_device.pub_key, my_device.priv_key = self.CA.generate_keys_for_id(device_id)
        sign_msg = b'Testing'
        sign_msg2 = b'TestinG'
        s, t = my_device.sign(sign_msg)
        self.assertTrue(verify(s, device_id, t, sign_msg, self.CA.pub_key.n))
        self.assertFalse(verify(s, device_id, t, sign_msg2, self.CA.pub_key.n))

    def test_signature_fails_on_other_id(self):
        device_id = "abcdefghijklmnoprstuvwxyz"
        my_device = Device(device_id)
        my_device.pub_key, my_device.priv_key = self.CA.generate_keys_for_id(device_id)
        device_id2 = "abcdefghijklmnoprstuvwxyy"
        my_device2 = Device(device_id2)
        my_device2.pub_key, my_device2.priv_key = self.CA.generate_keys_for_id(device_id)
        sign_msg = b'Testing'
        s, t = my_device.sign(sign_msg)
        self.assertFalse(verify(s, device_id2, t, sign_msg, self.CA.pub_key.n))

if __name__ == '__main__':
    unittest.main()