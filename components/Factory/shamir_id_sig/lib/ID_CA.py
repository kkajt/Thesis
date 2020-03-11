from .id_signatures import initialise_CA_key_pair, get_device_private_key, write_key_to_file, read_key_from_file, get_device_public_key

class ID_CA():

    def __init__(self):
        pass

    def generate_master_keys(self, e=65537):
        self.e = e
        self.priv_key, self.pub_key = initialise_CA_key_pair(e)
    
    def generate_keys_for_id(self, id):
        return get_device_public_key(id, self.pub_key), get_device_private_key(self.priv_key, id)


    def write_keys_to_files(self, pub_key_filename, priv_key_filename):
        if hasattr(self, "priv_key") and hasattr(self, "pub_key"):
            write_key_to_file(pub_key_filename, self.pub_key)
            write_key_to_file(priv_key_filename, self.priv_key)
        else:
            raise AttributeError("CA has not been initialised with the keys.")

    def import_keys_from_files(self, pub_key_filename, priv_key_filename):
        self.pub_key = read_key_from_file(pub_key_filename)
        self.priv_key = read_key_from_file(priv_key_filename)