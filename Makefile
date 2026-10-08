.DEFAULT_GOAL := all

CA_DIR := ca
CA_KEY := $(CA_DIR)/private/ca.key
CA_CRT := $(CA_DIR)/certs/ca.crt
CA_CNF := ca.cnf

.PRECIOUS: $(CA_KEY)

.phony: all dirs ca service client clean

all: dirs ca service client

dirs:
	mkdir -p $(CA_DIR)/certs $(CA_DIR)/crl $(CA_DIR)/newcerts $(CA_DIR)/private
	touch $(CA_DIR)/index.txt
	echo 1000 > $(CA_DIR)/serial

# Root CA: P-384, 10-year validity, SHA-384
ca: dirs $(CA_KEY)
	openssl req -x509 -new -sha384 -days 3650 -key $(CA_KEY) -out $(CA_CRT) -config $(CA_CNF) -extensions v3_ca
	ln -sfn ca.crt $(CA_DIR)/cacert.pem

$(CA_KEY):
	mkdir -p $(CA_DIR)/private
	openssl ecparam -name prime256v1 -genkey -noout -out $(CA_KEY)
	chmod 600 $(CA_KEY)

# Service cert for the GATEONE verifier (serverAuth)
service: ca
	openssl req -new -newkey ec -name prime256v1 -keyout gateone-server.key -out gateone-server.csr -nodes -config $(CA_CNF) -reqexts server_cert
	openssl ca -batch -config $(CA_CNF) -extensions server_cert -days 90 -in gateone-server.csr -out gateone-server.crt
	rm gateone-server.csr

# Client cert for Keycloak (clientAuth) - used by the script authenticator
client: ca
	openssl req -new -newkey ec -name prime256v1 -keyout keycloak-client.key -out keycloak-client.csr -nodes -config $(CA_CNF) -reqexts client_cert
	openssl ca -batch -config $(CA_CNF) -extensions client_cert -days 90 -in keycloak-client.csr -out keycloak-client.crt
	rm keycloak-client.csr

# Revoke a cert and regenerate the CRL
revoke:
	@read -p "Enter cert to revoke (e.g. gateone-server.crt): " cert; \
	openssl ca -config $(CA_CNF) -revoke $$cert
	openssl ca -config $(CA_CNF) -gencrl -out $(CA_DIR)/crl/ca.crl.pem

# Show the CA cert fingerprint for pinning
fingerprint: ca
	openssl x509 -in $(CA_CRT) -noout -fingerprint -sha384

clean:
	rm -rf $(CA_DIR) gateone-server.* keycloak-client.*
