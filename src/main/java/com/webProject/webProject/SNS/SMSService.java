package com.webProject.webProject.SNS;

import net.nurigo.java_sdk.api.Message;
import net.nurigo.java_sdk.exceptions.CoolsmsException;
import org.json.simple.JSONObject;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Random;

@Service
public class SMSService {
    private String apiKey = "NCSENQ4RHKHSNKBO";

    private String apiSecret = "G52URTCEZ7TTGWETM0J4MCDJHGJFQPIM";

    public String createRandomNumber() {
        Random rand = new Random();
        String randomNum = "";
        for (int i = 0; i < 4; i++) {
            String random = Integer.toString(rand.nextInt(10));
            randomNum += random;
        }

        return randomNum;
    }

    public String sendMessage(String phoneNumber) {
        String verificationCodeSMS = createRandomNumber();
        Message coolsms = new Message(apiKey, apiSecret);
        HashMap<String, String> params = new HashMap();
        params.put("to", phoneNumber);
        params.put("from", "01083175517");
        params.put("type", "SMS");
        params.put("text", "[팀프로젝트] 인증번호는 " + "["+verificationCodeSMS+"]" + " 입니다.");

        try {
          JSONObject obj = (JSONObject) coolsms.send(params);
        } catch (CoolsmsException e) {
          e.printStackTrace();
        }

        return verificationCodeSMS;
    }
}