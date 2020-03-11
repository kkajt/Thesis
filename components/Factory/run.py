from Factory_TA import Factory_TA

# requires pub_key.txt and priv_key.txt RSA keys to be in /keys directory
if __name__ == "__main__":
    factory = Factory_TA("./keys/pub_key.pem", "./keys/priv_key.key")
    factory.start_interactive_mode()