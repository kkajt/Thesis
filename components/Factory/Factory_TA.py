import socket
import re
import pickle
import os
import codecs
from shamir_id_sig.lib.ID_CA import ID_CA

class Factory_TA():

    SOCKET_BUFFER_SIZE = 4096
    DEV_KEY_PATH = './dev_keys/'
    ID_db = './dev_keys/id_list.txt'
    MASTER_PUB_KEY = None
    MASTER_PRIV_KEY = None

    def __init__(self, MASTER_PUB_KEY='./keys/test_pub.pem', MASTER_PRIV_KEY='./keys/test_priv.key', start_interactive=True):
        self.MASTER_PRIV_KEY = MASTER_PRIV_KEY
        self.MASTER_PUB_KEY = MASTER_PUB_KEY

        paths = [self.MASTER_PRIV_KEY, self.MASTER_PUB_KEY]

        non_existing_paths = []
        for filename in paths:
            if not os.path.exists(filename):
                non_existing_paths.append(filename)
        if non_existing_paths:
            print("Can't run program. The following files are missing:")
            for filename in non_existing_paths:
                print(filename)
            self.quit_program()
        
        if not os.path.exists(self.DEV_KEY_PATH):
            os.mkdir(self.DEV_KEY_PATH)

        self.CA = ID_CA()
        self.load_keys(self.MASTER_PUB_KEY, self.MASTER_PRIV_KEY)
        if start_interactive:
            self.start_interactive_mode()

    def load_keys(self, pub_key_file, priv_key_file):
        self.CA.import_keys_from_files(pub_key_file, priv_key_file)
    
    def generate_key_for_sensor(self, manual = True, ip = None, port = None):
        print("Generating key for device.")        
        device_id = input("Insert device ID: ")
        if not self.validate_id(device_id):
            print("Requested ID is not valid.")
            return
        print("Generating key for device ID: " + device_id +"...")

        dev_pub_key, dev_priv_key = self.CA.generate_keys_for_id(device_id)
        print("Keys generated successfully.")
        print("Saving keys to files...")
        self.save_device_keys_to_file((dev_pub_key, dev_priv_key), device_id)
        self.save_id_to_db(device_id)
        print("Key generation process finished successfully.")
   
    def validate_id(self, id):
        len_contrains = (10, 10)
        if len(id) < len_contrains[0]:
            print("ID is too short. Should be more than %d characters." % len_contrains[0])
            return False
        if len(id) > len_contrains[1]:
            print("ID is too long. Should be less than %d characters." % len_contrains[1])
            return False
        return True

    def save_device_keys_to_file(self, keys, device_id):
        dev_dir = self.DEV_KEY_PATH+device_id
        if not os.path.exists(dev_dir):
            os.mkdir(dev_dir)
        with open(dev_dir+"/id_pub.pem", "wb+") as file:
            public_id_key = (keys[0], device_id)
            file.write(codecs.encode(pickle.dumps(public_id_key), "base64"))
        with open(dev_dir +"/id_priv.key", "wb+") as file:
            file.write(codecs.encode(pickle.dumps(keys[1]), "base64"))
    
    def save_id_to_db(self, device_id):
        with open(self.ID_db, 'a') as file:
            file.write(device_id+"\n")

    def quit_program(self):
        raise SystemExit

    def invalid_choice(self):
        print("Inavlid choice!")
        self.display_menu()

    def parse_rsp(self, response):
        # deserialization
        return pickle.loads(response)

    def start_interactive_mode(self):
        print("Starting Factory CA in interactive mode.")
        self.display_menu()
    
    def display_menu(self):
        while(True):
            print("Menu:")
            menu = {
                "1": ("Generate key for new device", self.generate_key_for_sensor),
                "2": ("Exit", self.quit_program)
            }
            for key in sorted(menu.keys()):
                print(key+" - " + menu[key][0])
            ans = input("Choice: ")
            menu.get(ans,[None,self.invalid_choice])[1]()


if __name__ == "__main__":
    pass