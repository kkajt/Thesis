import shamir_id_sig.lib.id_signatures as Signatures

class Device():
    priv_key = ()
    pub_key = ()

    def __init__(self, id = ""):
        self.id = id

    def sign(self, m):
        if not self.priv_key or not self.pub_key:
            raise AttributeError("Device has not been initialised with key pair.")
        s, t = Signatures.sign(self.priv_key[0], m, self.pub_key[1], self.pub_key[2])
        return s, t


