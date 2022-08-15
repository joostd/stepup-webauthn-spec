<?php
include("../vendor/autoload.php");
include("../common.php");

use Base64Url\Base64Url;
use CBOR\CBOREncoder;

session_start();
error_log("============================== REGISTER ==============================");

// attestation truststore -- this should be stored in the database
$truststore = json_decode( file_get_contents("../truststore.json"), TRUE);
// error_log(print_r($truststore,TRUE));

if( isset($_POST['credId']) ) { // new registration with credId, clientDataJSON, and attestationObject
    error_log(print_r($_POST,true));
    // error_log(print_r($_SERVER,true));

    // clientDataJSON, containing type, challenge, and origin
    // The client data represents the contextual bindings of both the WebAuthn Relying Party and the client.
    $clientDataJSON = hex2bin($_POST['clientDataJSON']);
    $clientData = json_decode($clientDataJSON,true);
    error_log(print_r($clientData,true));
    assert($clientData['type'] === 'webauthn.create');
    assert($clientData['origin'] === $_SERVER['HTTP_ORIGIN']);
    $challenge = $clientData['challenge'];
    assert( Base64Url::decode($challenge) === $_SESSION['challenge'] );
    // unset($_SESSION['challenge']);

    // attestationObject, containing fmt, attStmt, authData
    $encodedAttestationObject = hex2bin($_POST['attestationObject']);
    $attestationObject = CBOREncoder::decode($encodedAttestationObject,true);
    error_log("attestationObject has properties: " . implode(",",array_keys($attestationObject)));
    error_log("fmt=".$attestationObject['fmt']);
    // assert( in_array($attestationObject['fmt'], ["none", "packed", "fido-u2f", "android-safetynet", "android-key"]) );	// only consider packed and fido-u2f for now, ignoring tpm, android-key, android-safetynet, none

    // Attestation Statement
    $attStmt = (array) $attestationObject['attStmt'];
    error_log("attStmt has properties: " . implode(",",array_keys($attStmt)));

    // The authenticator data structure encodes contextual bindings made by the authenticator 
    $authData = $attestationObject['authData']->get_byte_string();
    error_log("authData: " . bin2hex($authData));

    // todo: move to library functions

    // parse $authData
    $s = $authData; // copy $authData for destruction

    $rpIdHash = shiftn($s,32);
    error_log('rpIdHash = ' . bin2hex($rpIdHash));
    $flags = ord(shiftn($s,1));
    error_log('flags = ' . ($flags));
    $up = ($flags & 0x01); // user presence
    $uv = ($flags & 0x04); // user verification
    $at = ($flags & 0x40); // attestation
    $ed = ($flags & 0x80); // extensions
    assert( $up ); // user presence: UP == 1
    error_log("ED=$ed AT=$at UV=$uv UP=$up");
    assert( !$ed ); // no extensions
    
    $signCount = shiftn($s,4);
    error_log('signCount = ' . bin2hex($signCount));
    $signCount = unpack("N",$signCount)[1]; // unsigned long (always 32 bit, big endian byte order)

    error_log('signCount = ' . ($signCount));
    assert(strlen($s) > 0); // for registration, attestedCredentialData must be present
    $attestedCredentialData = $s; // assuming no extensions
    error_log('attestedCredentialData = ' . bin2hex($attestedCredentialData));

    // The attestedCredentialData field contains the credentialId and credentialPublicKey.
    $aaguid = shiftn($s,16); // Authenticator Attestation Globally Unique ID (AAGUID) 
    // TODO: use aaguid to look up a metadata statementin the FIDO Metadata Service
    error_log('aaguid = ' . bin2hex($aaguid)); // all 0s for attestation "none"
    $credentialIdLength = shiftn($s,2);
    error_log('credentialIdLength = ' . bin2hex($credentialIdLength));
    $length = unpack("n",$credentialIdLength)[1]; // unsigned short (always 16 bit, big endian byte order)
    error_log("length = $length");
    $credentialId = shiftn($s,$length);
    error_log("credentialId = " . bin2hex($credentialId));
    $credentialPublicKey = $s;
    error_log('credentialPublicKey = ' . bin2hex($credentialPublicKey));
    $credentialPublicKey = \CBOR\CBOREncoder::decode($credentialPublicKey);
    
    assert($credentialPublicKey[KTY] == EC2);
    assert($credentialPublicKey[ALG] == ES256);
    assert($credentialPublicKey[CRV] == P256);
    $x = bin2hex($credentialPublicKey[X]->get_byte_string());
    $y = bin2hex($credentialPublicKey[Y]->get_byte_string());
    error_log("x=$x; y=$y");
    
    if( $attestationObject['fmt'] === "packed") { // process packed attestation
        if( array_key_exists('x5c', $attStmt)) { // Attestation types Basic, AttCA - supported
            // attStmt contains alg, sig, x5c (for full attestation)
            $alg = $attStmt['alg'];
            error_log("algorithm is: $alg");
            $sig = $attStmt['sig']->get_byte_string();
            error_log("sig: " . bin2hex($sig));
            $x5c = $attStmt['x5c'];
            error_log("#certs: " . count($x5c));
            assert(count($x5c) >= 1);
            // packed attestation carries a complete certificate chain, first cert is Attestation Certificate, rest is CA chain
            $attestnCert = array_shift($x5c);
            $der = $attestnCert->get_byte_string();
            error_log("cert: " . bin2hex($der));
            // Validate attestation certificate against Trust Store
            $attestnCertHash = hash( 'sha256', $der );
            error_log("attestnCertHash: " . $attestnCertHash);
            // TODO: use attestationCertificateKeyIdentifiers instead of hashes to match metadata service spec?
            // assert( array_key_exists($attestnCertHash, $truststore) ); // the attestation certificate MUST be whitelisted

            $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der),64) . "-----END CERTIFICATE-----\n";
            error_log( $pem );

            // Attestation validation:
            // The attestation certificate is accepted if either
            // (1) the certificate validates to a registered CA using FIDO2 metadata
            // (2) the certificate validates to a whitelisted CA
            // (3) the certificate matches a whitelisted certificate
            $certificate = openssl_x509_read($pem);
            $openssl_cadir = '../u2f-cas';
            // TODO: validate attestation certificate against FIDO2 Metadata directory
            $valid = openssl_x509_checkpurpose($certificate,0,array($openssl_cadir));
            error_log("openssl_x509_checkpurpose: $valid");
            if($valid !== TRUE) {
                // probably self signed or unknown CA. Check whitelist
                error_log("U2F attestation certificate does not validate against a known CA");
                if( !isset( $truststore[$attestnCertHash])) { // unknown token, dump certificate details for inspection
                    error_log( "Attestation Certificate:" . PHP_EOL . $pem );
                    $certificate = openssl_x509_parse($pem);
                    error_log( print_r( $certificate, true ));
                    echo "Attestation Certificate not accepted";
                    exit();    
                }
            }
            
            error_log( "Accepting AAGUID ".bin2hex($aaguid)." [".$truststore[$attestnCertHash]['description']."]" );
            assert( $truststore[$attestnCertHash]['aaguid'] == bin2hex($aaguid) ); // double check on trust store contents
            $certificate = openssl_x509_parse($pem);
            while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
            // error_log( print_r( $certificate, true ));
            assert($certificate['version'] === 2);	// 0x02 == version 3
            assert($certificate['subject']['OU'] === 'Authenticator Attestation');
            assert($certificate['extensions']['basicConstraints'] === 'CA:FALSE');
            if( array_key_exists('1.3.6.1.4.1.45724.1.1.4', $certificate['extensions']) ) {
                $fido_gen_ce_aaguid = $certificate['extensions']['1.3.6.1.4.1.45724.1.1.4'];
                error_log("id-fido-gen-ce-aaguid: " . bin2hex($fido_gen_ce_aaguid));
                assert( bin2hex($fido_gen_ce_aaguid) == "0410" . bin2hex($aaguid) ); // AAUID in certificate MUST match AAGUID in authenticator data (with ASN.1 OCTET STRING prefix)
            }
            $publicKey = openssl_pkey_get_public($pem);
            while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
            assert($publicKey!==FALSE);
            $publicKeyArray = openssl_pkey_get_details($publicKey);
            if( $publicKeyArray['ec']['curve_name'] !== 'prime256v1') { // in case of unimplemented EC algo, dump pubkey for inspection
                error_log("openssl_pkey_get_details:" . print_r(openssl_pkey_get_details($publicKey), TRUE));
            }
            // dump CA chain
            foreach($x5c as $c) {
                $der = $c->get_byte_string();
                error_log("cert: " . bin2hex($der));
                $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64) . "-----END CERTIFICATE-----\n";
                error_log( $pem );
            }
            // verify attestation signature against public key in certificate
            $clientDataHash = hash( 'sha256', $clientDataJSON, true );
            $signedData = $authData . $clientDataHash;
            error_log("signedData=".bin2hex($signedData));
            error_log("signature=".bin2hex($sig));
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
            $result = openssl_verify($signedData, $sig, $publicKey, OPENSSL_ALGO_SHA256); // alg -7 == ES256
            while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
            error_log(print_r("verify:".$result,TRUE));
            assert($result===1);
        } else { // attestation type ECDAA or Self - unsupported
            error_log("Unsupported attestation type (Self of ECDAA)");
        }
    } elseif( $attestationObject['fmt'] === "fido-u2f") { // in case of legacy tokens
        $sig = $attStmt['sig']->get_byte_string();
        error_log("sig: " . bin2hex($sig));
        $x5c = $attStmt['x5c'];
        assert(count($x5c) == 1); // fido-u2f attestation carries a single certificate (no CA chain)
        $attestnCert = array_shift($x5c);
        $der = $attestnCert->get_byte_string();
        error_log("cert: " . bin2hex($der));
        // Validate U2F attestation certificate against Trust Store
        $attestnCertHash = hash( 'sha256', $der );
        error_log("attestnCertHash: " . $attestnCertHash);
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der)) . "-----END CERTIFICATE-----\n";
        $certificate = openssl_x509_read($pem);
        $openssl_cadir = '../u2f-cas';
        // validate attestation certificate against U2F CA directory
        // This should validate Yubico U2F security keys using https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
        $valid = openssl_x509_checkpurpose($certificate,0,array($openssl_cadir));
        error_log("openssl_x509_checkpurpose: $valid");
        if($valid !== TRUE) {
            // probably self signed or unknown CA. Check whitelist
            error_log("U2F attestation certificate does not validate against a known CA");
            if( !isset( $truststore[$attestnCertHash])) { // unknown token, dump certificate details for inspection
                error_log( "Attestation Certificate:" . PHP_EOL . $pem );
                $certificate = openssl_x509_parse($pem);
                error_log( print_r( $certificate, true ));
                echo "Attestation Certificate not accepted";
                exit();    
            }
        }
        $publicKey = openssl_pkey_get_public($pem);
        while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
        assert($publicKey!==FALSE);
        $publicKeyArray = openssl_pkey_get_details($publicKey);
        assert($publicKeyArray['ec']['curve_name'] === 'prime256v1');
        if( $publicKeyArray['ec']['curve_name'] !== 'prime256v1') { // in case of unimplemented EC algo, dump pubkey for inspection
            error_log("openssl_pkey_get_details:" . print_r(openssl_pkey_get_details($publicKey), TRUE));
        }
        $publicKeyU2F = hex2bin('04'.$x.$y);
        $clientDataHash = hash( 'sha256', $clientDataJSON, true );
        $verificationData = chr(0) . $rpIdHash . $clientDataHash . $credentialId . $publicKeyU2F; 
        error_log("verificationData=".bin2hex($verificationData));
        error_log("signature=".bin2hex($sig));
        $result = openssl_verify($verificationData, $sig, $publicKey, OPENSSL_ALGO_SHA256); // alg -7 == ES256
        while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
        error_log(print_r("verify:".$result,TRUE));
        assert($result===1);
    } elseif( $attestationObject['fmt'] === "android-safetynet") { // typically when using Chrome on Android
        // although unsupported, log details to ease future implementation
        // https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
        // https://www.w3.org/TR/webauthn/#android-safetynet-attestation
        $version = $attStmt['ver'];
        error_log("version: $version");
        $response = $attStmt['response']->get_byte_string();
        #error_log("response: $response");
        list($header, $payload, $signature) = explode('.',$response);
        $header = json_decode(base64_decode(strtr($header, "-_", "+/")), TRUE);
        $payload = json_decode(base64_decode(strtr($payload, "-_", "+/")), TRUE);
        error_log("JWT header: " . print_r($header, TRUE));
        // TODO verify JWT signature
        error_log("JWT payload: " . print_r($payload, TRUE));
        error_log("ctsProfileMatch: " . $payload['ctsProfileMatch']);
        error_log("basicIntegrity: " . $payload['basicIntegrity']);
        error_log("advice: " . $payload['advice']); // e.g. LOCK_BOOTLOADER, RESTORE_TO_FACTORY_ROM
	// LOCK_BOOTLOADER: check if OEM unlocking is enabled in developer options 

    // TODO: Verify the SafetyNet attestation response
        // https://developer.android.com/training/safetynet/attestation#verify-attestation-response
        // 
        echo "Attestation Format '" . $attestationObject['fmt'] . "' not supported";
        exit();
    } elseif( $attestationObject['fmt'] === "android-key") { // in case user declined attestation
        // certificate contains an extension with OID 1.3.6.1.4.1.11129.2.1.17
        // https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster2.h
        echo "Attestation Format '" . $attestationObject['fmt'] . "' not supported";
        exit();
    } elseif( $attestationObject['fmt'] === "none") { // in case user declined attestation
        error_log("No attestation!");
        // exit();
    } else {
        echo "Unknown Attestation Format";
        exit();
    }

    assert( isset($_SESSION['user_id']));
    $user_id = $_SESSION['user_id'];
    $filename = "/tmp/" . bin2hex($user_id) . ".json";
    $entry = json_decode( file_get_contents($filename), TRUE);
    $user_name = $entry['user']['name'];
    $displayName = $entry['user']['displayName'];
    
    // todo: store the credentialPublicKey with the credentialId in the account for this user (instead of EC params x,y)
    $entry['credential'] = [
            'id' => bin2hex($credentialId),
            'x' => $x,
            'y' => $y,
            'signCount' => $signCount,
            'attestationObject' => $_POST['attestationObject'], // store verbatim attestation object to allow for future re-evaluation of trust
    ];
    error_log(print_r($entry,TRUE));
    file_put_contents($filename, json_encode($entry));

    echo "$displayName ($user_name/" . bin2hex($user_id) . ") <a href='login.php'>login</a> | <a href='register.php'>register</a> | <a href='restart.php'>restart</a>";
    exit();
}
?>
<!-- client side part -->
<?php

if(!isset($_SESSION['user_id'])) {
    error_log("generating new user handle");
    $user_id = random_bytes(16);  // A user handle is an opaque byte sequence with a maximum size of 64 bytes. 
    $_SESSION['user_id'] = $user_id;

    $user_name = base_convert(time(), 10, 36); // use timestamp as userid
    $displayName = "User " . time()%1000 ;  // intended for display

    $entry = [
        'user' => [
            'id' => bin2hex($user_id),
            'name' => $user_name,
            'displayName' => $displayName,
        ]
    ];
    $filename = "/tmp/" . bin2hex($user_id) . ".json"; // todo remove duplicate code
    file_put_contents($filename, json_encode($entry));
    symlink($filename, "/tmp/$user_name.json");            
} else {
    $user_id = $_SESSION['user_id'];
    $filename = "/tmp/" . bin2hex($user_id) . ".json";
    $entry = json_decode( file_get_contents($filename), TRUE);
    $user_name = $entry['user']['name'];
    $displayName = $entry['user']['displayName'];    
}

$challenge = random_bytes(32); // must be a cryptographically random number sent from a server
error_log("new challenge: " . bin2hex($challenge));
$_SESSION['challenge'] = $challenge;
?>
<script>
if( navigator.credentials==undefined ) console.error("credentials API unavailable");
if (!window.PublicKeyCredential) console.error("Web Authentication API unavailable");

PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(console.log).catch(console.error);

function bufferToHex (buffer) {
    return Array
        .from (new Uint8Array (buffer))
        .map (b => b.toString (16).padStart (2, "0"))
        .join ("");
}

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const ES256 = -7;  // ECDSA      w/ SHA-256
const PS256 = -37; // RSASSA-PSS w/ SHA-256	(as used in Windows Hello)

// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#Examples
// sample arguments for registration
var createCredentialDefaultArgs = {

    publicKey: {
        // Relying Party (a.k.a. - Service):
        rp: {	// required
            name: "localhost demo",
	    // optional: id, not used - default is fine (i.e. current domain)
	    // optional: icon, not used
        },

        // User:
        user: {	// required
            id: new Uint8Array([ <?= bin2intList($user_id) ?> ]).buffer, // unique, opaque, not intended for display, match with userHandle in Assertion
            name: "<?= $user_name ?>",	      // intended for display
            displayName:  "<?= $displayName ?>" // intended for display
	    // optional: icon, not used
        },

        pubKeyCredParams: [
            {	// required
                type: "public-key",
                alg: ES256
            },
        ],

    	// this is needed to whitelist authenticators by vendor/certification etc (default is none)
        // attestation: "direct", // optional

	    // this is required to obtain a uniform experience across browsers. 60 seconds seem like a reasonable value, but this should be configurable
        timeout: 60000, // optional

    	// required:
        challenge: new Uint8Array([ <?= bin2intList($challenge) ?> ]).buffer,

        // optional:
        authenticatorSelection: {
        //  requireResidentKey: true, // default is false
          userVerification: "discouraged", // default is preferred
          authenticatorAttachment: "cross-platform", // either platform or cross-platform
        },
	    // not used:
    	// excludeCredentials, not needed as long as we do not allow more than one registered authenticator
	    // authenticatorSelection, defaults are fine, i.e. authenticatorAttachmentOptional can be either platform or cross-platform, requireResidentKeyOptional=false, userVerificationOptional=preferred
	    // extensions, eg AppId, not needed as we have no legacy U2F tokens registered in production
    }
};

// register / create a new credential
console.log(createCredentialDefaultArgs);

var makeCreds = () => {

    navigator.credentials.create(createCredentialDefaultArgs)
    .then((cred) => {
        console.log(cred); // PublicKeyCredential
        // id and type inherited from Credential interface
        console.log("id: " + cred.id); // base64urlencoded
        console.log("type: " + cred.type); // "public-key"
        //
        console.log("rawId: " + bufferToHex(cred.rawId)); // ArrayBuffer
        console.log("response: " + cred.response);	// AuthenticatorAttestationResponse
        if(!window.safari) // not implemented on Safari
            console.log(cred.getClientExtensionResults()); // Object {} - not using any extensions
        // clientDataJSON inherited from AuthenticatorResponse
        console.log("clientDataJSON: " + bufferToHex(cred.response.clientDataJSON)); // ArrayBuffer
        console.log("attestationObject: " + bufferToHex(cred.response.attestationObject)); // ArrayBuffer
        // cred.id, clientDataJSON, and attestationObject are sent back to server
        document.getElementById("registerForm").elements.namedItem("credId").value = cred.id;
        document.getElementById("registerForm").elements.namedItem("clientDataJSON").value = bufferToHex(cred.response.clientDataJSON);
        document.getElementById("registerForm").elements.namedItem("attestationObject").value = bufferToHex(cred.response.attestationObject);
    }).catch((err) => {console.error("oops:" + err)});
}

</script>

<div id="container">
    <h1>Register</h1>

    <div id="result" class="status" hidden></div>
    <button id="register" hidden>Register</button>
    <button class="btn btn-primary" onclick="makeCreds()">Create Credentials</button>

    <form id="registerForm" method="post">
    <input type="hidden" name="clientDataJSON" value="" />
    <input type="hidden" name="attestationObject" value="" />
    <input type="hidden" id="credId" name="credId" value="" />
    <input type="submit" value="submit" />
</form>

</div>
