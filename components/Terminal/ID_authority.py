from shamir_id_sig.lib.id_signatures import read_key_from_file, f

class ID_authority():
    def __init__(self):
        pass
    
    def init_from_file(self, pub_key_file):
        self.pub_key = read_key_from_file(pub_key_file)
    
    def set_default_one_way_func(self):
        self.func = f
