<?php

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
define("ES256", -7);  // ECDSA      w/ SHA-256
define("PS256", -37); // RSASSA-PSS w/ SHA-256
// https://tools.ietf.org/html/rfc8152#section-7
define("KTY",  1, TRUE); // key type
define("ALG",  3, TRUE); // key usage restriction to this algorithm
define("CRV", -1, TRUE); // curve to be used with the key
define("X",   -2, TRUE); // y-coordinate for the EC point.  
define("Y",   -3, TRUE); // y-coordinate for the EC point.  
// https://tools.ietf.org/html/rfc8152#section-13 (table 21)
define("EC2", 2, TRUE); // Elliptic Curve Keys w/ x- and y-coordinate pair 
// https://tools.ietf.org/html/rfc8152#section-13.1 (table 22)
define("P256", 1, TRUE); // NIST P-256 also known as secp256r1 



// convert binary string to an integer list for rendering as javascript Uint8Array
function bin2intList($s) {
    return implode(",", array_map('ord',str_split($s)) );
}

function shiftn(string &$s, $n) {
    $a = substr($s,0,$n);
    $s = substr_replace( $s, '', 0, $n);
    return $a;
  }
  