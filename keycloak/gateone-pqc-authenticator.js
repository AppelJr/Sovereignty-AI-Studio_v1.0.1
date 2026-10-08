// File: gateone-pqc-authenticator.js
// Deploy in Keycloak standalone under: providers/ or as part of a custom JAR
//
// GATEONE PQC Verifier Script Authenticator
// Calls the GATEONE FastAPI endpoint (gateone_pqc_verifier.py) to verify
// ML-DSA-87 (Dilithium) signatures + TPM 2.0 attestation quotes.
//
// STATUS: INTEGRATION STUB — not production-ready.
// - Requires Keycloak Script Authenticator feature enabled (feature flag).
// - Requires the GATEONE verifier running and reachable from the Keycloak host.
// - The verifier fails closed: TPM quote missing/invalid => valid=false.
// - mTLS client cert, bearer auth, and retry/timeout hardening added in v0.2.
// - Deploy only in a lab/dev environment until endpoint auth and hostname
//   are addressed.

var JavaString = Java.type("java.lang.String");
var URL = Java.type("java.net.URL");
var HttpsURLConnection = Java.type("java.net.HttpsURLConnection");
var SSLContext = Java.type("java.net.ssl.SSLContext");
var KeyManagerFactory = Java.type("java.net.ssl.KeyManagerFactory");
var TrustManagerFactory = Java.type("java.net.ssl.TrustManagerFactory");
var KeyStore = Java.type("java.security.KeyStore");
var FileInputStream = Java.type("java.io.FileInputStream");
var BufferedReader = Java.type("java.io.BufferedReader");
var InputStreamReader = Java.type("java.io.InputStreamReader");

/**
 * GATEONE PQC Verifier Script Authenticator (v0.2)
 *
 * Expects the client to supply an attestation_token form parameter
 * (JSON string: payload, signature, public_key, optional tpm_quote).
 * POSTs it to GATEONE_VERIFIER_URL/verify-attestation with:
 *   - mTLS client certificate (GATEONE_CLIENT_CERT_PATH / GATEONE_CLIENT_KEY_PATH)
 *   - Bearer token (GATEONE_VERIFIER_TOKEN)
 * On valid=true: context.success() and optionally sets user attributes.
 * On anything else: context.failure().
 */
function authenticate(context) {
    var httpRequest = context.getHttpRequest();
    var form = httpRequest.getDecodedFormParameters();

    var attestationToken = form.getFirst("attestation_token");
    if (!attestationToken) {
        context.failure();
        return;
    }

    // Configure via environment or edit before deploy:
    var GATEONE_VERIFIER_URL = "https://YOUR_GATEONE_HOST/verify-attestation";
    var GATEONE_VERIFIER_TOKEN = "YOUR_VERIFIER_BEARER_TOKEN";
    var GATEONE_CLIENT_CERT_PATH = "/path/to/gateone-client.p12";
    var GATEONE_CLIENT_CERT_PASSWORD = "YOUR_CLIENT_CERT_PASSWORD";
    var GATEONE_CA_CERT_PATH = "/path/to/ca.crt";

    try {
        // --- mTLS setup ---
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(GATEONE_CLIENT_CERT_PATH),
                      GATEONE_CLIENT_CERT_PASSWORD.toCharArray());
        var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, GATEONE_CLIENT_CERT_PASSWORD.toCharArray());

        var trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        var caCert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(new FileInputStream(GATEONE_CA_CERT_PATH));
        trustStore.setCertificateEntry("gateone-ca", caCert);
        var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        var url = new URL(GATEONE_VERIFIER_URL);
        var conn = url.openConnection();
        if (conn instanceof HttpsURLConnection) {
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
        }
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + GATEONE_VERIFIER_TOKEN);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);

        var payload = JSON.stringify({
            attestation_token: attestationToken,
            max_age_seconds: 300
        });

        var os = conn.getOutputStream();
        os.write(new JavaString(payload).getBytes("UTF-8"));
        os.flush();
        os.close();

        var responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            context.failure();
            return;
        }

        var reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        var responseBuilder = "";
        var line;
        while ((line = reader.readLine()) != null) {
            responseBuilder += line;
        }
        reader.close();

        var responseJson = JSON.parse(responseBuilder);

        if (responseJson && responseJson.valid === true) {
            var user = context.getUser();
            if (responseJson.node_id) {
                user.setSingleAttribute("pqc_node_id", responseJson.node_id);
            }
            if (responseJson.algorithm) {
                user.setSingleAttribute("pqc_algorithm", responseJson.algorithm);
            }
            context.success();
        } else {
            context.failure();
        }

    } catch (e) {
        LOG.error("GATEONE PQC verification failed", e);
        context.failure();
    }
}
