import unittest

from shamir_id_sig.lib.ID_CA import ID_CA
from shamir_id_sig.lib.id_signatures import read_key_from_file


class TestCAKeyGeneration(unittest.TestCase):
    test_pub_key_file = "./keys/test_pub.txt"
    test_priv_key_file = "./keys/test_priv.txt"

    def setUp(self):
        my_CA = ID_CA()
        my_CA.generate_master_keys()
        my_CA.write_keys_to_files(self.test_pub_key_file, self.test_priv_key_file)

    def test_read_write_keys(self):
        pub_key_file = "./keys/test_read_write_pub.txt"
        priv_key_file = "./keys/test_read_write_priv.txt"
        my_CA = ID_CA()
        my_CA.generate_master_keys()
        my_CA.write_keys_to_files(pub_key_file, priv_key_file)
        read_pub_key = read_key_from_file(pub_key_file)
        read_priv_key = read_key_from_file(priv_key_file)
        self.assertEqual(my_CA.pub_key.exportKey("PEM"), read_pub_key.exportKey("PEM"))
        self.assertEqual(my_CA.priv_key.exportKey("PEM"), read_priv_key.exportKey("PEM"))

    def test_CA_keys(self):
        my_CA = ID_CA()
        my_CA.import_keys_from_files(self.test_pub_key_file, self.test_priv_key_file)
        _, id_priv_key1 = my_CA.generate_keys_for_id("abcdefghijklmnoprstuvwxyz")
        _, id_priv_key2 = my_CA.generate_keys_for_id("abcdefghijklmnoprstuvwxyy")
        self.assertNotEqual(id_priv_key1, id_priv_key2)
        
if __name__ == '__main__':
    unittest.main()