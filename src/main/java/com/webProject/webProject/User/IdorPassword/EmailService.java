package com.webProject.webProject.User.IdorPassword;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    @Autowired
    private JavaMailSender javaMailSender;

    public String sendVerificationCode(String toEmail, String verificationCode) {
        System.out.println("Verification code: " + verificationCode); // 로그로 출력
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("이메일 인증번호");
        message.setText("임시 인증번호: " + verificationCode);
        javaMailSender.send(message);
        return verificationCode;
    }
    public String sendVerificationCodeSMS(String phone) {
        String storedVerificationCode = String.valueOf((int) (Math.random() * 9000) + 1000);

        System.out.println("Verification code for phone number " + phone + ": " + storedVerificationCode);
        return storedVerificationCode;
    }
}
