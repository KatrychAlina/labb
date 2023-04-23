<?php
namespace PHPMailer\src;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require './PHPMailer/src/PHPMailer.php';
require './PHPMailer/src/SMTP.php';
require './PHPMailer/src/Exception.php';

class M
{
    public function send_email($address, $content)
    {
        try {
            $mail = new PHPMailer(true);
            $mail->isSMTP(); // Set mailer to use SMTP
            $mail->Host = 'poczta.o2.pl'; // Specify main and backup SMTP servers
            $mail->SMTPAuth = true; // Enable SMTP authentication
            $mail->Username = 'konto_email_do_wysyłania_maili@o2.pl'; // SMTP username
            $mail->Password = 'hasło do konta do wysyłki'; // SMTP password
            $mail->SMTPSecure = 'tls'; // Enable encryption, 'ssl' also accepted
            $mail->CharSet = 'UTF-8';
            $mail->setFrom('konto_email_do_wysyłania_maili@o2.pl', 'OTP source');
            $mail->addAddress($address); // Add a recipient
            $mail->WordWrap = 40; // Set word wrap to 40 characters
            $mail->isHTML(true); // Set email format to HTML
            $mail->Subject = 'Your security code';
            $mail->Body = 'This is your authentication code <b>'.$content.'</b>';
            $mail->AltBody = 'This is your authentication code '.$content.'';
            $mail->send();
            echo 'Message has been sent';
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }
}

$m = new M();
$m->send_email('adres_odbiorcy@gmail.com', 'hasło jednorazowe');
