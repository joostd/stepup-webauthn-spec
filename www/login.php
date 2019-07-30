<?php
include("../vendor/autoload.php");
include("../common.php");

use Base64Url\Base64Url;
use CBOR\CBOREncoder;

session_start();

$entry = json_decode( file_get_contents("/tmp/entry.json"), TRUE);
error_log(print_r($entry,TRUE));

if( array_key_exists('user_id',$_SESSION)) {
    $user_id = $_SESSION['user_id'];
    error_log("user id: " . bin2hex($user_id));
} else {
    error_log("user id unavailable"); // instruct user to register first (ignored here, as we have a single entry)
}

if( $_POST['signature'] ) { // new login with signature, clientDataJSON, and authenticatorData
    error_log(print_r($_POST,true));
    $signature = hex2bin($_POST['signature']);

    // clientDataJSON, containing type, challenge, and origin
    $clientDataJSON = hex2bin($_POST['clientDataJSON']);
    $clientData = json_decode($clientDataJSON,true);
    error_log(print_r($clientData,true));
    assert($clientData['type'] === 'webauthn.get');
    assert($clientData['origin'] === $_SERVER['HTTP_ORIGIN']);
    $challenge = $clientData['challenge'];
    assert( Base64Url::decode($challenge) === $_SESSION['challenge'] );
    // unset($_SESSION['challenge']);
    
    $authenticatorData = (hex2bin($_POST['authenticatorData']));

    $s = $authenticatorData; // we're gonna destructively update $s
    $rpIdHash = shiftn($s,32);
    error_log('rpIdHash = ' . bin2hex($rpIdHash));
    $flags = shiftn($s,1);
    error_log('flags = ' . bin2hex($flags));
    assert($flags && 0x01 === 0x01); // user presence: UP == 1
    $signCount = shiftn($s,4);
    error_log('signCount = ' . bin2hex($signCount));
    $signCount = unpack("N",$signCount)[1]; // unsigned long (always 32 bit, big endian byte order)
    error_log('signCount = ' . ($signCount));
    // check and update signcount
    if( $signCount > 0) {
        assert( $signCount > $entry['credential']['signCount']); // using numerical ordering here
        $entry['credential']['signCount'] = $signCount;    
    } else {
        error_log('signCount ignored');
    }
    assert( $s === ''); // no extensions

    // TODO: verify signature over response 
    // verify that sig is a valid signature over the binary concatenation of authData and hash.
    $hash = hash( 'sha256', $authenticatorData . $clientDataJSON, true );
    error_log("hash=".bin2hex($hash));

    $hashId = hash('sha256', $_SERVER['HTTP_ORIGIN'], TRUE);
    $signeddata = $authData . hash('sha256', $clientdata, TRUE);

    // 3.	Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.

    $x = hex2bin($entry['credential']['x']);
    $y = hex2bin($entry['credential']['y']);
    error_log("x=".bin2hex($x));
    error_log("y=".bin2hex($y));

    $der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
    $der .= "\x00". chr(4).$x.$y;
    $pem  = "-----BEGIN PUBLIC KEY-----\x0A";
    $pem .= chunk_split(base64_encode($der), 64, "\x0A");
    $pem .= "-----END PUBLIC KEY-----\x0A";
    error_log("\n\n".$pem);

    // 4.	Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
    // 15.	Let hash be the result of computing a hash over the cData using SHA-256.
    $hash = hash( 'sha256', $clientDataJSON, true );
    // 16. Using the credential public $key looked up in step 3, verify that sig is a valid signature over the binary concatenation of authData and hash.
    error_log("data=".bin2hex($authenticatorData . $hash));
    error_log("signature=".bin2hex($signature));
    $publicKey = openssl_pkey_get_public($pem);
    while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
    assert($publicKey!==FALSE);
    error_log("openssl_pkey_get_details:" . print_r(openssl_pkey_get_details($publicKey), TRUE));
    $result = openssl_verify($authenticatorData . $hash, $signature, $publicKey, OPENSSL_ALGO_SHA256);
    while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
    error_log(print_r("verify:".$result,TRUE));
    assert($result===1);

    // updating account store
    error_log(print_r($entry,TRUE));
    file_put_contents("/tmp/entry.json", json_encode($entry));

    echo "<a href='login.php'>login</a> | <a href='register.php'>register</a>";
    exit();
}

$challenge = random_bytes(32); // must be a cryptographically random number sent from a server
error_log(bin2hex($challenge));
$_SESSION['challenge'] = $challenge;
$credential_id = hex2bin($entry['credential']['id']);
?>
<!-- client side part -->
<script>
function bufferToHex (buffer) {
    return Array
        .from (new Uint8Array (buffer))
        .map (b => b.toString (16).padStart (2, "0"))
        .join ("");
}

// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#Examples
// sample arguments for login
var getCredentialDefaultArgs = {
    publicKey: {
       	// this is required for SURFsecureID to obtain a uniform experience across browsers. 60 seconds seem like a reasonable value, but this should be configurable
        timeout: 60000,
        // allowCredentials: retrieved from storage
        // can be multiple credentials but for now we only consider one credential per account
        // can also be empty for passwordless credentials, but we ignore those as well
        allowCredentials: [
            {
                id: new Uint8Array([ <?= bin2intList($credential_id) ?> ]).buffer,
                transports: ["usb", "nfc", "ble"],
                type: "public-key"
            }
        ],
        // required:
        challenge: new Uint8Array([ <?= bin2intList($challenge) ?> ]).buffer

       	// not used:
        // userVerification 
        // rpId 	    // optional: id, not used - default is fine (i.e. current domain)
       	// extensions, eg AppId, u2f, not needed as we have no legacy U2F tokens registered
    },
};

// login / use a previously registered credential
console.log(getCredentialDefaultArgs);
navigator.credentials.get(getCredentialDefaultArgs)
    .then((assertion) => {
        console.log(assertion);
        console.log("rawId: " + bufferToHex(assertion.rawId));
        console.log("id: " + assertion.id);
        console.log("type: " + assertion.type);
        console.log("response: " + assertion.response);	// AuthenticatorAssertionResponse
        console.log("clientDataJSON: " + bufferToHex(assertion.response.clientDataJSON));
        console.log("signature: " + bufferToHex(assertion.response.signature));
        console.log("authenticatorData: " + bufferToHex(assertion.response.authenticatorData));
        document.getElementById("loginForm").elements.namedItem("clientDataJSON").value = bufferToHex(assertion.response.clientDataJSON);
        document.getElementById("loginForm").elements.namedItem("signature").value = bufferToHex(assertion.response.signature);
        document.getElementById("loginForm").elements.namedItem("authenticatorData").value = bufferToHex(assertion.response.authenticatorData);
    }).catch((err) => {
        console.log("ERROR", err);
    });
</script>

<div id="container">
    <h1>Login</h1>

    <div id="result" class="status" hidden></div>
    <button id="login" hidden>Login</button>

    <form id="loginForm" method="post">
    <input type="hidden" name="clientDataJSON" value="" />
    <input type="hidden" name="signature" value="" />
    <input type="hidden" name="authenticatorData" value="" />
    <input type="submit" value="submit" />
</form>

</div>