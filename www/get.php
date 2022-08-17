<?php
include("../vendor/autoload.php");
include("../common.php");

use Base64Url\Base64Url;
use CBOR\CBOREncoder;

function pubkeyEC2($x, $y) {
    $der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
    $der .= "\x00". chr(4).$x.$y;
    $pem  = "-----BEGIN PUBLIC KEY-----\x0A";
    $pem .= chunk_split(base64_encode($der), 64, "\x0A");
    $pem .= "-----END PUBLIC KEY-----\x0A";
    // error_log("\n\n".$pem);
    $publicKey = openssl_pkey_get_public($pem);
    while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
    assert($publicKey!==FALSE);
    // error_log("openssl_pkey_get_details:" . print_r(openssl_pkey_get_details($publicKey), TRUE));
    return $publicKey;
}

function getUserById($id) { // $id in hex encoding
    $userfile = "/tmp/$id.json";
    error_log("retrieving user info from file $userfile");
    return json_decode( file_get_contents($userfile), TRUE);
}

function updateUser($user) { // $id in hex encoding
    $userfile = "/tmp/" . $user['user']['id'] . ".json";
    error_log("storing user info in file $userfile");
    file_put_contents($userfile, json_encode($user));
}

session_start();

// $user_id = null;
$credential_ids = [];

if( array_key_exists('user_id',$_SESSION)) { // logged in, so require a credential from a specific user
    $user_id = $_SESSION['user_id'];
    error_log("user id: " . bin2hex($user_id));
    $user = getUserById(bin2hex($user_id));
    $credential_ids = array_keys($user['credentials']);
    error_log(print_r($credential_ids,TRUE));
}

if( isset($_POST['signature']) ) { // new login with signature, clientDataJSON, and authenticatorData
    error_log(print_r($_POST,true));
    if( array_key_exists('userHandle',$_POST)) { // we have a passwordless login attempt
        $userHandle = $_POST['userHandle'];
    }
    if( isset($user_id) && isset($userHandle) )
        assert($user_id === $userHandle); // detect manipulation of post parameters. Passwordless should only be triggered when not logged in
    
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
        // $hashId = hash('sha256', $_SERVER['HTTP_ORIGIN'], TRUE);
    $flags = shiftn($s,1);
    error_log('flags = ' . bin2hex($flags));
    assert($flags && 0x01 === 0x01); // user presence: UP == 1
    $signCount = shiftn($s,4);
    error_log('signCount = ' . bin2hex($signCount));
    $signCount = unpack("N",$signCount)[1]; // unsigned long (always 32 bit, big endian byte order)
    error_log('signCount = ' . ($signCount));

    assert( $s === ''); // no extensions

    // verify that sig is a valid signature over the binary concatenation of authData and hash.
    // 3.	Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.

    $hash = hash( 'sha256', $clientDataJSON, true );
    $signedData = $authenticatorData . $hash;
    error_log("signed data=".bin2hex($signedData));
    error_log("signature=".bin2hex($signature));

    if( isset($user_id) ) {
        $user = getUserById(bin2hex($user_id));
    } else if( isset($userHandle) ) {
        $user = getUserById( $userHandle );
    } else {
        //???
    }
    $user_name = $user['user']['name'];
    $displayName = $user['user']['displayName'];
    $credentials = $user['credentials'];
    $credential_ids = array_keys($credentials);
    error_log(print_r($credential_ids,TRUE));

    $validCredential = FALSE;
    foreach( $credential_ids as $credential_id) {
        $x = hex2bin($user['credentials'][$credential_id]['x']);
        $y = hex2bin($user['credentials'][$credential_id]['y']);
        error_log("x=".bin2hex($x));
        error_log("y=".bin2hex($y));
        $publicKey = pubkeyEC2($x,$y);
        $result = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        while($msg = openssl_error_string() !== false) error_log("openssl error: $msg"); # flush openssl errors
        error_log(print_r("verify:".$result,TRUE));
        if ($result===1) {
            $validCredential = TRUE;
            if( $user_id === null ) $user_id = hex2bin($userHandle);
            error_log("valid signature for credential $credential_id");
            // check and update signcount
            if( $signCount > 0) {
                assert( $signCount > $user['credentials'][$credential_id]['signCount']); // using numerical ordering here
                $user['credentials'][$credential_id]['signCount'] = $signCount;    
            } else {
                error_log('signCount ignored');
            }
            break; // look no further
        }
    }

    // updating account store
    // error_log(print_r($user,TRUE));
    updateUser($user);

    if( $validCredential === TRUE)
        echo "<b>valid assertion</b><br/>";
        echo "$displayName ($user_name/" . bin2hex($user_id) . ") [#signatures: " . $signCount . "]<br/>";
        echo "<a href='logout.php'>logout</a> | <a href='get.php'>get credential</a> | <a href='create.php'>create credential</a>";
        exit();
}

$challenge = random_bytes(32); // must be a cryptographically random number sent from a server
error_log(bin2hex($challenge));
$_SESSION['challenge'] = $challenge;


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
       	// this is required to obtain a uniform experience across browsers. 60 seconds seem like a reasonable value, but this should be configurable
        timeout: 60000,
        // allowCredentials: retrieved from storage
        // can be multiple credentials but for now we only consider one credential per account
        // can also be empty for passwordless credentials, but we ignore those as well
        allowCredentials: [
    <?php foreach($credential_ids as $credential_id): ?>
            {
                id: new Uint8Array([ <?= bin2intList(hex2bin($credential_id)) ?> ]).buffer,
                transports: ["usb", "nfc", "ble"],
                type: "public-key"
            },
    <?php endforeach; ?>
        ],
        // required:
        challenge: new Uint8Array([ <?= bin2intList($challenge) ?> ]).buffer,

        // optional:
        userVerification: "discouraged" // default is preferred

       	// not used:
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
        console.log("userHandle: " + bufferToHex(assertion.response.userHandle)); // empty unless discoverable credential was used
        document.getElementById("loginForm").elements.namedItem("clientDataJSON").value = bufferToHex(assertion.response.clientDataJSON);
        document.getElementById("loginForm").elements.namedItem("signature").value = bufferToHex(assertion.response.signature);
        document.getElementById("loginForm").elements.namedItem("authenticatorData").value = bufferToHex(assertion.response.authenticatorData);
        document.getElementById("loginForm").elements.namedItem("userHandle").value = bufferToHex(assertion.response.userHandle);

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
    <input type="hidden" name="userHandle" value="usedfordiscoverablecredentials" />
    <input type="submit" value="submit" />
</form>

</div>
