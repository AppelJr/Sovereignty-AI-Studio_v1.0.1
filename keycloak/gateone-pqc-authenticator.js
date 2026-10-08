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
// - No mTLS, no authn on the verifier endpoint, no retry/timeout hardening.
// - Deploy only in a lab/dev environment until those are addressed.

var JavaString = Java.type("java.lang.String");
var URL = Java.type("java.net.URL");
var HttpURLConnection = Java.type("java.net.HttpURLConnection");
var BufferedReader = Java.type("java.io.BufferedReader");
var InputStreamReader = Java.type("java.io.InputStreamReader");

/**
 * GATEONE PQC Verifier Script Authenticator
 *
 * Expects the client to supply an attestation_token form parameter
 * (JSON string: payload, signature, public_key, optional tpm_quote).
 * POSTs it to GATEONE_VERIFIER_URL/verify-attestation.
 * On valid=true: context.success() and optionally sets user attributes.
 * On anything else: context.failure().
 */
function authenticate(context) {
    var httpRequest = context.getHttpRequest();
    var form = httpRequest.getDecodedFormParameters();

    var attestationToken = form.getFirst("attestation_token"); // Provided by client
    if (!attestationToken) {
        context.failure();
        return;
    }

    // Configure via environment or edit before deploy:
    var GATEONE_VERIFIER_URL = "https://YOUR_GATEONE_HOST/verify-attestation";

    try {
        var url = new URL(GATEONE_VERIFIER_URL);
        var conn = url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
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
            // Optionally set user attributes, e.g., node_id or algorithm
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
