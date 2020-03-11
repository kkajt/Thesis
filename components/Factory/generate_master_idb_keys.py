from shamir_id_sig.lib.ID_CA import ID_CA
import sys

if __name__ == "__main__":
    pub_key_path = input("Insert public key filename: \n")
    priv_key_path = input("Insert private key filename: \n")
    if pub_key_path == priv_key_path:
        print("Filenames must differ!")
        raise SystemExit
    TA = ID_CA() 
    TA.generate_master_keys()
    TA.write_keys_to_files(pub_key_path+".pem", priv_key_path+".key")