<?php

require_once 'C:\xampp\htdocs\app\htmlpurifier-4.15.0\library\HTMLPurifier.auto.php';
require_once 'Aes.php';

class Pdo_
{
    private $db;
    private $purifier;

    public function __construct()
    {
        $config = HTMLPurifier_Config::createDefault();
        $this->purifier = new HTMLPurifier($config);
        try {
            $this->db = new PDO('mysql:host=localhost;dbname=news', 'app_user', 'student');
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die();
        }
    }

public function add_user($login, $email, $password)
{
    $login = $this->purifier->purify($login);
    $email = $this->purifier->purify($email);

    // Hash the password using Argon2id
    $password_hash = password_hash($password, PASSWORD_ARGON2ID);

    // Store the hashed password
    try {
        $sql = "INSERT INTO user(login, email, hash, id_status, password_form)
            VALUES (:login, :email, :hash, :id_status, :password_form)";

        $stmt = $this->db->prepare($sql);
        $id_status = 1;
        $password_form = "HASHED";
        $stmt->bindParam(':login', $login);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':hash', $password_hash);
        $stmt->bindParam(':id_status', $id_status);
        $stmt->bindParam(':password_form', $password_form);
        $stmt->execute();
    } catch (PDOException $e) {
        echo "Error: " . $e->getMessage();
    }
}

public function log_user_in($login, $password) {
    $login = trim($this->purifier->purify($login));
    $password = trim($password);

    $sql = "SELECT * FROM user WHERE login = :login";
    $stmt = $this->db->prepare($sql);
    $stmt->execute(array(':login' => $login));

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $hash = $row['hash'];
        if (password_verify($password, $hash)) {
            // poprawne logowanie
            session_start();
            $_SESSION['user_id'] = $row['id_user'];
            $_SESSION['user_login'] = $row['login'];
            header('Location: login.php');
            exit();
        } else {
            // nieprawidłowe hasło
            echo "Incorrect password";
        }
    } else {
        // użytkownik o podanym loginie nie istnieje
        echo "User does not exist";
    }
}


public function log_2F_step1($login,$password){
 $login=$this->purifier->purify($login);
 try {
 $sql="SELECT id,hash,login,salt,email FROM user WHERE login=:login";
 $stmt= $this->db->prepare($sql);
 $stmt->execute(['login'=>$login]);
 $user_data=$stmt->fetch();
 $password_hash = hash('sha512', $password . $user_data['salt']);
 if($password==$user_data['hash']){
 //generate and send OTP
 $otp=random_int(100000, 999999);
 $code_lifetime=date('Y-m-d H:i:s', time()+300);
 try{
 $sql="UPDATE `user` SET `sms_code`=:code,
`code_timelife`=:lifetime WHERE login=:login";
 $data= [
 'login' =>$login,
 'code' =>$otp,
 'lifetime' =>$code_lifetime
 ];
 $this->db->prepare($sql)->execute($data);
 //add the code to send an e-mail with OTP
 $result= [
 'result'=>'success'
 ];
 return $result;
 } catch (Exception $e) {
 print 'Exception' . $e->getMessage();
 //add necessary code here
 }
 }else{
 echo 'login FAILED<BR/>';
 $result= [
 'result'=>'failed'
 ];
 return $result;
 }
 } catch (Exception $e) {
 print 'Exception' . $e->getMessage();
 //add necessary code here
 }
 }
 
 public function log_2F_step2($login,$code){
 $login=$this->purifier->purify($login);
 $code=$this->purifier->purify($code);
 try {
 $sql="SELECT id,login,sms_code,code_timelife
FROM user WHERE login=:login";
 $stmt= $this->db->prepare($sql);
 $stmt->execute(['login'=>$login]);
$user_data=$stmt->fetch();
 if($code==$user_data['sms_code']
&&time()< strtotime($user_data['code_timelife'])){
 //login successfull
 echo 'Login successfull<BR/>';
 return true;
 }else{
 echo 'login FAILED<BR/>';
 return false;
 }
 } catch (Exception $e) {
 print 'Exception' . $e->getMessage();
 }
 }


public function change_password($login, $old_password, $new_password)
{
    $login = $this->purifier->purify($login);

    try {
        $sql = "SELECT id,hash,salt FROM user WHERE login=:login";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['login' => $login]);
        $user_data = $stmt->fetch();

        $old_password = hash('sha512', $old_password . $user_data['salt']);
        if ($old_password != $user_data['hash']) {
            echo 'Old password is incorrect<BR/>';
            return;
        }

        $salt = bin2hex(random_bytes(32));
        $new_hash = hash('sha512', $new_password . $salt);

        $sql = "UPDATE user SET hash=:hash, salt=:salt WHERE id=:id";
        $data = [
            'hash' => $new_hash,
            'salt' => $salt,
            'id' => $user_data['id'],
        ];
        $this->db->prepare($sql)->execute($data);

        echo 'Password changed successfully<BR/>';
    } catch (Exception $e) {
        
        print 'Exception' . $e->getMessage();
    }
}

}
