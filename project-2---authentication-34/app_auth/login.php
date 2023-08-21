<?php
  
$servername = "localhost";
$username = "username";
$password = "password";
$dbname = "dados.sb";
  
// Create connection
$conn = new SQLite3($servername, $username, $password, $dbname);
  
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " 
        . $conn->connect_error);
}
  
$sqlquery = "INSERT INTO info VALUES ('John', 'Doe')";
  
if ($conn->query($sql) === TRUE) {
    echo "record inserted successfully";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}
