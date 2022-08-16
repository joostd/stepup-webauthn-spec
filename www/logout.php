<?php
session_start();

unset($_SESSION['user_id']);
?>
<br/>
<a href='login.php'>login</a> |
<a href='get.php'>get credential</a> | 
<a href='create.php'>create credential</a>