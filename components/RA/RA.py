import re, pickle, socket, string, random, os
from shamir_id_sig.lib.id_signatures import verify, read_key_from_file
from OpenSSL import crypto
from shamir_id_sig.lib.asn1crypto_idb_custom.csr_structures import *
from certs_handling_RA import createCertificate, verify_csr_sensor, verify_csr_terminal
from ID_authority import ID_authority
import time


class RA():

    SOCKET_BUFFER_SIZE = 4096
    authority = None
    ROOT_CA_CERT = "./certs/ca/root-ca.crt" # Path to root CA cert to send to device
    CA_CERT = './certs/signing-ca/signing-ca.crt'
    CA_PRIV_KEY = './certs/ca/private/signing-ca.key'
    SIGNED_CERTS = './certs/signed/'
    CA_BUNDLE = './certs/ca/signing-ca.ca-bundle'
    PROD_KEY = './certs/producents/Thesis_Producent/pub_key.key'
    CSR_PATH = './csr/'

    def __init__(self, ROOT_CA_CERT = "./certs/ca/root-ca.crt", CA_CERT = './certs/ca/signing-ca.crt', \
            CA_PRIV_KEY='./certs/ca/signing-ca/private/signing-ca.key', SIGNED_CERTS='./certs/signed/', \
            CA_BUNDLE='./certs/ca/signing-ca.ca-bundle', PROD_KEY='./certs/producents/Thesis_Producent/pub_key.pem', \
            CSR_PATH = './csr/'
            ):
        self.ROOT_CA_CERT = ROOT_CA_CERT
        self.CA_CERT = CA_CERT
        self.CA_PRIV_KEY = CA_PRIV_KEY
        self.SIGNED_CERTS = SIGNED_CERTS
        self.CA_BUNDLE = CA_BUNDLE
        self.PROD_KEY = PROD_KEY
        self.CSR_PATH = CSR_PATH


        if not os.path.exists(self.CSR_PATH):
            os.mkdir(self.CSR_PATH)

        certs = [self.ROOT_CA_CERT, self.CA_CERT, self.CA_PRIV_KEY, self.SIGNED_CERTS, self.CA_BUNDLE, self.PROD_KEY, self.PROD_KEY]
        non_existing_certs = []
        for cert in certs:
            if not os.path.exists(cert):
                non_existing_certs.append(cert)
        if non_existing_certs:
            print("Can't run program. The following certs are missing:")
            for cert in non_existing_certs:
                print(cert)
            self.quit_program()     
        id_authority = ID_authority()
        id_authority.init_from_file(self.PROD_KEY)
        id_authority.set_default_one_way_func()
        self.authority = id_authority  

    def choose_csr(self):
        while(True):
            onlycsr = [f for f in os.listdir(self.CSR_PATH) if os.path.isfile(os.path.join(self.CSR_PATH, f)) and f.endswith('.csr')]
            if len(onlycsr) == 0:
                return None
            i = 1
            for csr in onlycsr:
                print(str(i) + ". " +csr)
                i += 1
            try:
                id = int(input("Choose csr ID: "))
                if id > len(onlycsr) or id < 1:
                    print("Wrong ID. Try again.")
                else:
                    return onlycsr[id-1]
            except ValueError:
                print("Wrong input.")

    def create_cert_for_terminal_init(self):
        print("Starting certificate generation procedure...")
        csr_id = self.choose_csr()
        if csr_id == None:
            print("No csr files available.")
            return
        req = self.read_csr_from_file(csr_id, idb = False)
        if self.verify_terminal(req):
            cert = self.gen_cert_terminal(req)
        else:
            print("Certificate signing request validation error. Can't create certificate.")

    def create_cert_for_sensor(self, idb = True):
        print("Starting certificate generation procedure...")
        csr_id = self.choose_csr()
        if csr_id == None:
            print("No csr files available.")
            return
        req = self.read_csr_from_file(csr_id, idb)

        factory_pub_key = self.load_prod_key()
        if self.verify_device_signature(req, factory_pub_key):
            cert = self.gen_cert_sensor(req.dump())
        else:
            print("Certificate signing request validation error. Can't create certificate.")

    def read_csr_from_file(self, filename, idb):
        with open(self.CSR_PATH+filename) as f:
            csr_pem = bytes(f.read(), 'utf-8')
        if idb:
            _, _, der_bytes = pem.unarmor(csr_pem)
            req = IDBCertificationRequest.load(der_bytes)
        else:
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)
        return req

    def verify_terminal(self, req):
        return verify_csr_terminal(req)

    def send_close_msg(self, conn):
        msg = {"msg": "CLOSE"}
        self.send_json_message(msg, conn)
        conn.close()

    def read_cert_from_file(self, file):
        with open(file, 'rt') as f:
            st_cert = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
        return cert
    
    def read_priv_key_from_file(self, file):
        try:
            with open(file, 'rt') as f:
                st_key = f.read()
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, st_key)
            return key
        except:
            print("Can't read the keys.")
            raise Exception()

    def gen_cert_sensor(self, req):
        '''
            req - pem format
        '''
        print("Generating certificate for the request...")
        req = crypto.load_certificate_request(crypto.FILETYPE_ASN1, req)
        ca_cert = self.read_cert_from_file(self.CA_CERT)
        try:
            ca_pkey = self.read_priv_key_from_file(self.CA_PRIV_KEY)
        except:
            print("Can't read private key. Aborting....")
            self.quit_program()
        cert = createCertificate(req, ca_cert, ca_pkey, 1, 0, 60*60*24*365*5)
        print("Saving generated certificate...")
        with open(self.SIGNED_CERTS+getattr(req.get_subject(), 'CN')+'.cert', 'wb+') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        print("Certificate created and saved.")
        return cert
    
    def gen_cert_terminal(self, req):
        print("Generating certificate for the request...")
        ca_cert = self.read_cert_from_file(self.CA_CERT)
        try:
            ca_pkey = self.read_priv_key_from_file(self.CA_PRIV_KEY)
        except:
            print("Can't read private key. Aborting....")
            self.quit_program()
        cert = createCertificate(req, ca_cert, ca_pkey, 1, 0, 60*60*24*365*5)
        print("Saving generated certificate...")
        open(self.SIGNED_CERTS+getattr(req.get_subject(), 'CN')+'.cert', 'wb+').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        print("Certificate created and saved.")
        return cert

    def verify_device_signature(self, req, prod_pub_key):
        return verify_csr_sensor(req, prod_pub_key)
    
    def parse_rsp(self, response):
        # deserialization
        return pickle.loads(response)

    def validate_ip(self, ip, port):
        ip_regex = r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z"
        return re.search(ip_regex, ip) and int(port) < 65535 and int(port) > 1

    def connect_to_device_interactive(self):
        '''
        Requests sensors IP and PORT, connects and verifies first message
        returns socket and response message
        '''
        print("Please insert device IP and PORT address.")
        while(True):
            ip = input("IP: ")
            port = input("PORT: ")
            if self.validate_ip(ip, port):
                break
            else:
                print("Wrong IP! Try again.")
        
        s, rsp = self.connect_to_device(ip, int(port))

        return s, rsp 

    def connect_to_device(self, ip, port):
        print("Trying to reach " + ip + ":" + str(port))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
        except socket.gaierror:
            print("Address-related error connecting to server.")
            raise Exception()
        except socket.error:
            print("Connection error.")
            raise Exception()
        
        rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
        print("Connected to the device.")
        if rsp['msg'] != 'SERVERHELLO' or not rsp['state']:
            s.close()
            print(str(rsp))
            raise ValueError("Unexpected server response.")
        return s, rsp

    def install_trust_anchor_init(self, manual=True, ip='', port=None):
        try:
            if manual:
                s, rsp = self.connect_to_device_interactive()
            else:
                s, rsp = self.connect_to_device(ip, port)
        except:
            print("Connection error. Try again")
            return
        print("Device ID: " + rsp['id'])
        msg = {'msg': 'INSTALL_TRUST_ANCHOR'}
        self.send_json_message(msg, s)
        rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
        if rsp['msg'] == "OK":
            self.install_trust_anchor(s)
        else: 
            print("Device refuses to install trust anchor. Verify and try again.")
            s.close()
            return

    def install_trust_anchor(self, s):

        self.send_file_over_socket(s, self.ROOT_CA_CERT)
        rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
        if rsp['msg'] == "OK":
            print("Trust anchor installed successfully")
        else:
            print("There was some problem with anchor installation in Device. Please verify it and try again.")
        s.close()

    def load_prod_key(self):
        return read_key_from_file(self.PROD_KEY)
    
    def send_file_over_socket(self, s, filename):
        print("Sending file " + filename)
        filesize = os.path.getsize(filename)
        filesize = bin(filesize)[2:].zfill(32) # encode filesize as 32 bit binary
        s.send(filesize.encode())
        time.sleep(0.25)
        with open(filename, 'rb') as f:
            l = f.read()
            s.sendall(l)
        print("File sent")

    def send_json_message(self, msg, conn):
        conn.sendall(pickle.dumps(msg))

    def quit_program(self):
        raise SystemExit

    def invalid_choice(self):
        print("Inavlid choice!")
        self.display_menu()

    def start_interactive_mode(self):
        print("Starting RA in interactive mode.")
        self.display_menu()
    
    def display_menu(self):
        while(True):
            print("Menu:")
            menu = {
                "1": ("Install trust anchor on device", self.install_trust_anchor_init),
                "2": ("Create certificate for new sensor", self.create_cert_for_sensor),
                "3": ("Create certificate for new terminal", self.create_cert_for_terminal_init),
                "4": ("Exit", self.quit_program)
            }
            for key in sorted(menu.keys()):
                print(key+" - " + menu[key][0])
            ans = input("Choice: ")
            menu.get(ans,[None,self.invalid_choice])[1]()

if __name__ == "__main__":
    pass