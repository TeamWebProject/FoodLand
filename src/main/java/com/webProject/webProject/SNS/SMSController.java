package com.webProject.webProject.SNS;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Controller
@RequiredArgsConstructor
public class SMSController {

    private final SMSService smsService;
    //클라이언트가 휴대전화 번호(phoneNumber)를 파라미터로 전달하면, createRandomNumber() 메서드를 통해 랜덤한 인증 코드를 생성하고, SMS 서비스(smsService)를 통해 해당 번호로 메시지를 전송합니다.


    @GetMapping("/send")
    public String send(@RequestParam String phoneNumber, HttpSession session) {
        String verificationCodeSMS = this.smsService.createRandomNumber();
        smsService.sendMessage(phoneNumber);
        //생성된 인증 코드는 세션에 저장됩니다
        session.setAttribute("verificationCodeSMS", verificationCodeSMS);
        //마지막으로, "/"로 리다이렉트되어 홈 페이지로 이동합니다.
        return "redirect:/";
    }


    //클라이언트는 세션에서 이전에 생성된 인증 코드를 가져오기 위해 이 엔드포인트에 요청할 수 있습니다.
    //세션에서 "verificationCodeSMS" 속성을 가져와 JSON 형태로 응답합니다.
    @GetMapping("/sendVerKey")
    public ResponseEntity<Map<String, String>> getVerificationKey(HttpSession session) {
        String verificationCodeSMS = (String) session.getAttribute("verificationCodeSMS");

        Map<String, String> response = new HashMap<>();
        response.put("verificationCodeSMS", verificationCodeSMS);
        return ResponseEntity.ok(response);
    }
}
