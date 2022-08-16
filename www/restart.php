<?php
session_start();

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
    ],
    'credentials' => [],
];

$userfile = "/tmp/" . bin2hex($user_id) . ".json";
file_put_contents($userfile, json_encode($entry));
symlink($userfile, "/tmp/$user_name.json");            

?>
<a href='login.php'>login</a> | <a href='register.php'>register</a>