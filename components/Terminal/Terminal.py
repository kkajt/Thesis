import random, string, socket, re, pickle
from shamir_id_sig.lib.id_signatures import verify
from shamir_id_sig.lib.asn1crypto_idb_custom.csr_structures import *
import ssl
from OpenSSL import crypto
from certs_handling import *
import sys
import os
import time
from certvalidator import CertificateValidator, ValidationContext


class Terminal():

    SOCKET_BUFFER_SIZE = 4096
    ID = '12345'
    HOST = ''	# Symbolic name meaning all available interfaces
    PORT = 8889	# Arbitrary non-privileged port
    CA_BUNDLE_PATH = None
    TRUST_ANCHOR_FILE = None
    PKI_CERT = None
    PKI_PRIV_KEY = None
    PKI_PUB_KEY = None
    PKI_CSR_PATH = None
    DEV_CSR_PATH = None
    DEV_CERT_PATH = None
    state = 1
    DEV_CA_BUNDLE_NAME = 'signing-ca.ca-bundle'
    ORG_NAME = 'Thesis_Client'
    COMMON_NAME = 'Terminal1'

    def __init__(self, CA_BUNDLE_PATH='./certs/anchor/signing-ca.ca-bundle', PKI_CERT_PATH='./certs/',
                TRUST_ANCHOR_FILE = './certs/anchor/root-ca.crt',
                PKI_PRIV_KEY='./certs/terminal_priv_key.key', PKI_PUB_KEY='./certs/terminal_pub_key.pem', 
                DEV_CSR_PATH='./dev_csr', DEV_CERT_PATH = './certs/dev_certs/', 
                PKI_CSR_PATH = './csr/'):
        self.CA_BUNDLE_PATH = CA_BUNDLE_PATH
        self.TRUST_ANCHOR_FILE = TRUST_ANCHOR_FILE
        self.PKI_PRIV_KEY = PKI_PRIV_KEY
        self.DEV_CSR_PATH = DEV_CSR_PATH
        self.DEV_CERT_PATH = DEV_CERT_PATH
        self.PKI_PUB_KEY = PKI_PUB_KEY
        self.PKI_CSR_PATH = PKI_CSR_PATH
        self.PKI_CERT = PKI_CERT_PATH+self.COMMON_NAME+'.cert'

        if os.path.exists(self.CA_BUNDLE_PATH):
            self.state = 2
            print("Trust anchor detected.")
            if os.path.exists(self.PKI_CERT) and os.path.exists(self.PKI_PRIV_KEY):
                print("Certificates and trust anchor detected.")
                if self.verify_certs():
                    self.state = 3
                else:
                    print("Certificate verification failure.")
        print("Terminal started.")
        print("Initial state: "+ str(self.state))

    def verify_certs(self):
        pub_key = self.read_pub_key_from_file(self.PKI_PUB_KEY)
        
        with open(self.PKI_CERT, 'rb+') as f:
            cert_raw = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_raw)

        verified = True
        cert_pub_key = cert.get_pubkey()

        if not self.verify_ca_bundle(self.TRUST_ANCHOR_FILE, self.CA_BUNDLE_PATH, end_entity=self.PKI_CERT):
            print("Certificate verification fail: Certificate verification against certificate chain failed.")
            verified = False
        if cert.has_expired():
            print("Ceritficate verification fail: Certificate has expired.")
            verified = False

        if cert_pub_key.to_cryptography_key().public_numbers().n != pub_key.to_cryptography_key().public_numbers().n \
            or cert_pub_key.to_cryptography_key().public_numbers().e != pub_key.to_cryptography_key().public_numbers().e:
            print("Ceritficate verification fail: public keys doesn't match.")
            verified = False
        
        return verified

    def gen_cert_request(self, cname):
        print("Generating certificate sign request...")
        pkey = createKeyPair(TYPE_RSA, 1024)
        req = createCertRequest(pkey, CN=cname)
        with open(self.PKI_PRIV_KEY, 'wb+') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
        print("Generation completed.")
        return req
    
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
        
        return self.connect_to_device(ip, int(port))

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
            raise ValueError("Unexpected server response.")
        print("Device ID: " + rsp['id'])
        return s, rsp

    def generate_sign_message(self, message_len = 32):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(message_len))

    def send_json_message(self, msg, conn):
        conn.sendall(pickle.dumps(msg))

    def quit_program(self):
        raise SystemExit

    def invalid_choice(self):
        print("Inavlid choice!")
        self.display_menu()

    def request_sensor_csr(self, manual = True, ip='', port = None):
        if self.state != 3:
            print("Cannot perform TLS connection. This device doesn't have proper certificates installed.")
            return
        try:
            if manual:
                s, rsp = self.connect_to_device_interactive()
            else:
                s, rsp = self.connect_to_device(ip, port)
        except:
            print("Connection error. Try again")
            return
        dev_id = rsp['id']
        if rsp['state'] == 1:
            print("Can't verify the device because it has no ID-based private key.")
            self.send_close_msg(s)
            return
        elif rsp['state'] == 2:
            print("Can't create cert for sensor - there is no trust anchor on it.")
            self.send_close_msg(s)
            return
        elif rsp['state'] == 3 or rsp['state'] == 4:
            if rsp['state'] == 4:
                print("Sensor already has certificate. Request will be generated with RSA key pair.")
            if rsp['state'] == 3:
                print("Sensor doesn't have certificate. Request will be generated with IDB key pair.")
            print("Requesting certificate generation procedure...")
            msg = {'msg': 'GETCSR'}
            self.send_json_message(msg, s)
            rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
            if rsp['msg'] == 'OK':
                s = self.perform_tls_connection_client_verify(s)
                print("Requesting certificate signing request...")
                req = self.get_cert_req(s)
                self.save_csr(req, dev_id)
                
                msg = {'msg':"SUCCESS"}
                self.send_json_message(msg, s)

    def save_csr(self, req, dev_id):
        if not os.path.exists(self.DEV_CSR_PATH):
            os.mkdir(self.DEV_CSR_PATH)
        dev_dir = self.DEV_CSR_PATH+"/"+dev_id
        if not os.path.exists(dev_dir):
            os.mkdir(dev_dir)
        with open(dev_dir+"/"+dev_id+".csr", "wb+") as file:
            file.write(req)

    def get_cert_req(self, s, idb=True):
        msg = {'msg': 'CERT_DATA', 'certdata': {'org': 'Thesis', 'country': 'PL'}}
        self.send_json_message(msg, s)
        rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
        if rsp['msg'] == 'CERT REQUEST':
            csr_pem = s.recv(self.SOCKET_BUFFER_SIZE)   
            print("Got certificate signing request from sensor.")
            return csr_pem

    def start_interactive_mode(self):
        print("Starting Terminal in interactive mode.")
        if self.state == 1:
            print("Device doesn't have trust anchor installed. Please install it first.")
            print("It should be installed in under relative to main file: " + self.CA_BUNDLE_PATH)
            self.quit_program()
        while True:
            self.display_menu()
    
    def choose_cert(self):
        while(True):
            cert_dirs = [f for f in os.listdir(self.DEV_CERT_PATH) if os.path.isdir(os.path.join(self.DEV_CERT_PATH, f))]
            if len(cert_dirs) == 0:
                return None
            i = 1
            for cert_dir in cert_dirs:
                print(str(i) + ". " +cert_dir)
            try:
                id = int(input("Choose cert ID: "))
                if id > len(cert_dirs) or id < 1:
                    print("Wrong ID. Try again.")
                else:
                    return cert_dirs[id-1]
            except ValueError:
                print("Wrong input.")

    def verify_files_exist(self, dev_id, path):
        if os.path.exists(path+dev_id+'/'+self.DEV_CA_BUNDLE_NAME) and os.path.exists(path+dev_id+'/'+dev_id+'.cert'):
            return True
        else:
            return False

    def send_cert_to_sensor(self, manual = True):
        if self.state != 3:
            print("Cannot perform TLS connection. This device doesn't have proper certificates installed.")
            return
        cert_num = self.choose_cert()
        if cert_num == None:
            print("No certificates in device certificate directory available.")
            return
        if not self.verify_files_exist(cert_num, self.DEV_CERT_PATH):
            print("Wrong certificate files. Exiting procedure.")
            return
        try:
            if manual:
                s, rsp = self.connect_to_device_interactive()
            else:
                s, rsp = self.connect_to_device(ip, port)
        except:
            print("Connection error. Try again")
            return
        dev_id = rsp['id']
        if rsp['state'] == 1:
            print("Can't verify the device because it has no ID-based private key.")
            self.send_close_msg(s)
            return
        elif rsp['state'] == 2:
            print("Can't create cert for sensor - there is no trust anchor on it.")
            self.send_close_msg(s)
            return
        elif rsp['state'] == 3 or rsp['state'] == 4:
            msg = {'msg': 'INSTALL_CERT'}
            self.send_json_message(msg, s)
            rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
            if rsp['msg'] == "OK":
                print("Starting certificate installation procedure...")
                s = self.perform_tls_connection_client_verify(s)
                print("Sending CA-bundle file...")
                msg = {'msg': 'CA-BUNDLE'}
                self.send_json_message(msg, s)
                self.send_file_over_socket(s, self.DEV_CERT_PATH+cert_num+'/'+self.DEV_CA_BUNDLE_NAME)
                rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
                if rsp['msg'] == 'SUCCESS': 
                    print("Sending certificate...")
                    msg = {'msg': 'CERTIFICATE'}
                    self.send_json_message(msg, s)
                    with open(self.DEV_CERT_PATH+cert_num+'/'+cert_num+'.cert','rb') as f:
                        cert = f.read()
                    cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                    s.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM,cert_pem))
                    rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
                    if rsp['msg'] == 'SUCCESS':
                        print("Certificate and bundle successfully installed.")
                        s.close()
            else:
                print("Error while requesting certificate installation.")
                s.close()
    
    def read_priv_key_from_file(self, filename):
        try:
            with open(filename, 'rt') as f:
                st_key = f.read()
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, st_key)
            return key
        except:
            print("Can't read the keys.")
            raise Exception()

    def read_pub_key_from_file(self, filename):
        try:
            with open(filename, 'rt') as f:
                st_key = f.read()
            key = crypto.load_publickey(crypto.FILETYPE_PEM, st_key)
            return key
        except Exception as ex:
            print(ex)
            print("Can't read the keys.")
            raise Exception()

    def generate_csr(self):
        print("Generating certificate signing request with RSA signature...")            
        if not (os.path.exists(self.PKI_PRIV_KEY) and os.path.exists(self.PKI_PUB_KEY)):
            pkey= create_key_pair(1024)
            with open(self.PKI_PRIV_KEY, 'wb+') as f: 
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
            with open(self.PKI_PUB_KEY, 'wb+') as f: 
                f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, pkey))
        priv_key = self.read_priv_key_from_file(self.PKI_PRIV_KEY)
        pub_key = self.read_pub_key_from_file(self.PKI_PUB_KEY)
        req = create_csr_rsa(pub_key, priv_key, O=self.ORG_NAME, CN=self.COMMON_NAME)
        print("Generation completed.")
        print("Saving csr...")
        req_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        with open(self.PKI_CSR_PATH+self.COMMON_NAME+".csr", 'wb+') as f:
            f.write(req_pem)
        print("Request saved.")
        

    def display_menu(self):
        print("Menu:")
        menu = {
            "1": ("Generate CSR", self.generate_csr),
            "2": ("Encrypted connect to sensor", self.tls_connect_to_sensor_init),
            "3": ("Request sensor CSR", self.request_sensor_csr),
            "4": ("Send certificate to sensor", self.send_cert_to_sensor),
            "5": ("Exit", self.quit_program)
        }
        for key in sorted(menu.keys()):
            print(key+" - " + menu[key][0])
        ans = input("Choice: ")
        menu.get(ans,[None,self.invalid_choice])[1]()

    def tls_connect_to_sensor_init(self, manual=True, ip='', port=None):
        if self.state != 3:
            print("Cannot perform TLS connection. This device doesn't have proper certificates installed.")
            return
        try:
            if manual:
                s, rsp = self.connect_to_device_interactive()
            else:
                s, rsp = self.connect_to_device(ip, port)
        except:
            print("Connection error. Try again.")
            return
        if rsp['state'] != 4:
            print("Can't perform secure connection. The device has not proper certificate.")
            msg = {'msg': 'CLOSE'}
            self.send_json_message(msg, s)
            s.close()
            return
        print("Requesting TLS connection...")
        msg = {'msg': 'TLS_CONNECTION'}
        self.send_json_message(msg, s)
        rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
        if rsp['msg'] == 'OK':
            try:
                s = self.perform_tls_connection_two_way_verify(s)
                rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
                if rsp['msg'] == 'SUCCESS':
                    print("TLS connection established.")
                    self.receive_secrets(s)
                    s.close()
            except Exception as ex:
                print(ex)
                print("Aborting connection...")
                s.close()
                print("Connection closed.")

    def receive_secrets(self, s):
        print("Printing messages from sensor:")
        try:
            while(True):
                rsp = self.parse_rsp(s.recv(self.SOCKET_BUFFER_SIZE))
                print(rsp["secret"])
        except KeyboardInterrupt:
            pass
        except:
            print("Sensor has ended the connection.")
        print("Exiting connection.")

    def perform_tls_connection_two_way_verify(self, conn):
        return ssl.wrap_socket(conn,
                   ca_certs=self.CA_BUNDLE_PATH,
                   cert_reqs=ssl.CERT_REQUIRED,
                   certfile=self.PKI_CERT,
                   keyfile=self.PKI_PRIV_KEY 
                   )
    
    def perform_tls_connection_client_verify(self, conn):
        return ssl.wrap_socket(conn,
                    ca_certs=self.CA_BUNDLE_PATH,
                    cert_reqs=ssl.CERT_NONE,
                    certfile=self.PKI_CERT,
                    keyfile=self.PKI_PRIV_KEY,
                    server_side=True
                    )

    def parse_rsp(self, response):
        # deserialization
        return pickle.loads(response)

    def validate_ip(self, ip, port):
        ip_regex = r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z"
        return re.search(ip_regex, ip) and int(port) < 65535 and int(port) > 1

    def receive_file_over_socket(self, s, filename):
        with open(filename, 'wb+') as f:
            while True:
                print('Receiving data...')
                data = s.recv(1024)
                if not data:
                    break
                f.write(data)
        print("File received successfully.")

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

    def send_close_msg(self, conn):
        msg = {"msg": "CLOSE"}
        self.send_json_message(msg, conn)
        conn.close()

    def verify_ca_bundle(self, trust_anchor_file, chain_file, end_entity = None):
        end_entity_cert = None
        if end_entity is not None:
            with open(end_entity, 'rb') as f:
                type_name, headers, der_bytes = pem.unarmor(f.read())
                end_entity_cert = der_bytes
        intermediates = []
        with open(chain_file, 'rb') as f:
            for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):
                if end_entity_cert is None:
                    end_entity_cert = der_bytes
                else:
                    intermediates.append(der_bytes)
        
        trust_roots = []
        with open(trust_anchor_file, 'rb') as f:
            for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
                trust_roots.append(der_bytes)
        context = ValidationContext(trust_roots=trust_roots)
        
        try:
            validator = CertificateValidator(end_entity_cert, intermediate_certs=intermediates, validation_context=context)
            validator.validate_usage(set([]))
            return True
        except Exception as ex:
            print(ex)
            print("Certificate chain verification failed.")
            return False