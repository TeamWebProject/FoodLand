package com.webProject.webProject.User;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webProject.webProject.CustomUser;
import com.webProject.webProject.DataNotFoundException;
import com.webProject.webProject.SNS.SMSService;
import com.webProject.webProject.User.IdorPassword.EmailService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.HtmlUtils;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final EmailService emailService;
    private final SMSService smsService;

    @GetMapping("/owner_check_bno")
    public String owner_check_bno(OwnerCreateForm ownerCreateForm){
        return "user/owner_check_bno";
    }

    @PostMapping("/owner_check_bno")
    public String owner_check_bno(@Valid OwnerCreateForm ownerCreateForm, BindingResult bindingResult) {
        final String VALID_NUM = "01";
        try{
            String data = String.format("{\"businesses\":[{\"b_no\": \"%s\",\"start_dt\": \"%s\",\"p_nm\": \"%s\"}]}", HtmlUtils.htmlEscape(ownerCreateForm.getB_no()),
                    HtmlUtils.htmlEscape(ownerCreateForm.getStart_dt()), HtmlUtils.htmlEscape(ownerCreateForm.getP_nm()));
            //hhtpClient 객체 생성
            CloseableHttpClient httpClient = HttpClients.createDefault();

            //외부 api 가 존재하는 url
            String url ="https://api.odcloud.kr/api/nts-businessman/v1/validate?serviceKey=6EaPLiF5QZfSCQ1U9%2Fi2OHaHGHjsuguhUI%2FtFqreMA%2F84puk8RRN%2FnJ7sr0h7iU2lnXvsz2oPiHerQg1m%2BlG0g%3D%3D";
            HttpPost httpPost = new HttpPost(url);

            //content-type 정의 및 http body에 json 문자열 정의
            httpPost.addHeader("Content-Type","application/json");
            StringEntity entity = new StringEntity(data, StandardCharsets.UTF_8);
            httpPost.setEntity(entity);
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String response = httpClient.execute(httpPost, responseHandler);

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(response, Map.class);

            List<Map> dataList = (List<Map>)map.get("data");
            String result = (String)dataList.get(0).get("valid");

            if(!result.equals(VALID_NUM)){
                return "redirect:/user/owner_check_bno";
            }
        }catch (Exception e) {
            e.printStackTrace();
            // 예외 처리
        }
        return "redirect:/user/owner_signup";
    }

    @GetMapping("/owner_signup")
    public String owner_signup(UserCreateForm userCreateForm){
        return "user/owner_signup_form";
    }

    @PostMapping("/owner_signup")
    public String owner_signup(@Valid UserCreateForm userCreateForm, BindingResult bindingResult, MultipartFile file) throws Exception {
        if (bindingResult.hasErrors()) {
            return "user/owner_signup_form";
        }

        if (!userCreateForm.getPassword1().equals(userCreateForm.getPassword2())) {
            bindingResult.rejectValue("password2", "passwordInCorrect",
                    "2개의 패스워드가 일치하지 않습니다.");
            return "user/owner_signup_form";
        }

        userService.create(userCreateForm.getUserId(), userCreateForm.getEmail(), userCreateForm.getPassword1(), userCreateForm.getNickname(), "owner", userCreateForm.getPhone(), file);

        return "user/login_form";
    }
    @GetMapping("/user_signup")
    public String user_signup(UserCreateForm userCreateForm){
        return "user/user_signup_form";
    }
    @PostMapping("/user_signup")
    public String user_signup(@Valid UserCreateForm userCreateForm, BindingResult bindingResult, MultipartFile file) throws Exception {
        if (bindingResult.hasErrors()) {
            return "user/user_signup_form";
        }

        if (!userCreateForm.getPassword1().equals(userCreateForm.getPassword2())) {
            bindingResult.rejectValue("password2", "passwordInCorrect",
                    "2개의 패스워드가 일치하지 않습니다.");
            return "user/user_signup_form";
        }
        userService.create(userCreateForm.getUserId(), userCreateForm.getEmail(), userCreateForm.getPassword1(), userCreateForm.getNickname(), "user", userCreateForm.getPhone(), file);

        return "user/login_form";
    }

    @GetMapping("/signup")
    public String signup() {
        return "user/signup_form";
    }

    @GetMapping("/login")
    public String login() {
        return "user/login_form";
    }

    @GetMapping("/profile")
    public String profile(Authentication authentication, Principal principal, UserPasswordForm userPasswordForm, Model model){
        String userId = principal.getName();
        User userinfo = this.userService.getUser(userId);
        model.addAttribute("userinfo", userinfo);

        return "userProfile/profile";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/profile/modify")
    public String modifyProfile(Model model, UserUpdateForm userUpdateForm, UserPasswordForm userPasswordForm, Principal principal) {
        String userId = principal.getName();
        User userinfo = this.userService.getUser(userId);
        model.addAttribute("userinfo", userinfo);

        userUpdateForm.setNickname(userinfo.getNickname());
        userUpdateForm.setEmail(userinfo.getEmail());
        userPasswordForm.setPassword(userinfo.getPassword());
        return "userProfile/update_profile"; // 수정 폼으로 이동합니다.
    }

    // 사용자 프로필 정보 수정
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/profile/modify")
    public String modifyUserProfile(@Valid UserUpdateForm userUpdateForm, Authentication authentication, Principal principal, BindingResult bindingResult) throws Exception {
        String userId = principal.getName();
        User userinfo = this.userService.getUser(userId);
        if (bindingResult.hasErrors()) {
            return "userProfile/update_profile";
        }

        if (userUpdateForm.getImage() != null) {
            userinfo = this.userService.modify(userinfo, userUpdateForm.getNickname(), userUpdateForm.getEmail(), userUpdateForm.getImage());
        }
        if (authentication.getPrincipal() instanceof CustomUser) {
            CustomUser customUser = (CustomUser) authentication.getPrincipal();

            customUser.setNickname(userUpdateForm.getNickname());

            if (userUpdateForm.getImage() != null && !userUpdateForm.getImage().isEmpty()) {
                String fileName = userinfo.getFileName();
                customUser.setFileName(fileName);
            }
            Collection<? extends GrantedAuthority> authorities = customUser.getAuthorities();
            Authentication newAuthentication = new UsernamePasswordAuthenticationToken(customUser, authentication.getCredentials(), authorities);
            SecurityContextHolder.getContext().setAuthentication(newAuthentication);

            return "redirect:/user/profile";
        } else {
            return "error";
        }
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/profile/modify_pw")
    public String modifyUserPw(@Valid UserPasswordForm userPasswordForm, Principal principal, BindingResult bindingResult){
        String userId = principal.getName();
        User userinfo = this.userService.getUser(userId);

        if (bindingResult.hasErrors()) {
            return "userProfile/update_profile";
        }
        this.userService.modifyPw(userinfo, userPasswordForm.getNewPassword2());

        return "redirect:/user/profile/modify";
    }

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/profile/checkPassword")
    public ResponseEntity<String> checkPassword(@RequestBody UserPasswordForm userPasswordForm) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String userId = authentication.getName();
        User userinfo = this.userService.getUser(userId);

        if (userinfo == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        String storedPassword = userinfo.getPassword();
        if (storedPassword == null || storedPassword.isEmpty()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        if (passwordEncoder.matches(userPasswordForm.getPassword(), storedPassword)) {
            return ResponseEntity.ok("YES");
        } else {
            return ResponseEntity.ok("NO");
        }
    }
    @Value("${ImgLocation}")
    public String imgLocation;

    @PostMapping("/profile/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("image") MultipartFile file) throws IOException {
        // 새 이미지 파일 업로드
        String fileName = this.userService.uploadFile(file, imgLocation);
        if (fileName != null) {
            // 기존 이미지 파일 경로 설정
            String existingImagePath = imgLocation + fileName;
            System.out.println("Existing Image Path: " + existingImagePath);

            // 기존 이미지 파일 삭제
            boolean isDeleted = this.userService.deleteExistingFile(existingImagePath);
            if (isDeleted) {
                return ResponseEntity.ok(fileName); // 파일 이름 반환
            } else {
                return ResponseEntity.ok("Failed to delete existing image");
            }
        } else {
            return ResponseEntity.ok("NO"); // 실패 시 응답
        }
    }

    @RequestMapping("/findIdMethod")
    public String findIdMethod(@RequestParam("type") String type){
        if (type.equals("email")){
            return "user/findId_form";
        }
        return "user/findId_Phone";
    }
    @RequestMapping("/findPwMethod")
    public String findPwMethod(@RequestParam("type") String type){
        if (type.equals("email")){
            return "user/findPw_form";
        }
        return "user/findPw_Phone";
    }
    @PostMapping("/findId")
    public String findId(@RequestParam("verificationCode") String verificationCode, HttpSession session,
                         @RequestParam(value = "verificationCodeForm", required = false) boolean verificationCodeForm,
                         Model model) {
        // 세션에서 저장된 이메일 가져오기
        String userEmail = (String) session.getAttribute("userEmail");
        String storedVerificationCode = (String) session.getAttribute("verificationCode");


        List<User> userList = this.userService.findIdByEmail(userEmail);

        model.addAttribute("verificationCodeMismatch", false);
        model.addAttribute("verificationCodeForm", verificationCodeForm);
        model.addAttribute("email", userEmail);

        if(verificationCode.equals(storedVerificationCode)){
            model.addAttribute("userList",userList);
            model.addAttribute("verificationCodeForm",false);
        }

        if(!verificationCode.equals(storedVerificationCode)) {
            // 인증 코드 불일치 처리 (예: 에러 메시지 전달)
            model.addAttribute("verificationCodeMismatch", true);
            return "user/findId_form";
        }

        // 찾는 아이디 없을 때
        if(!userList.isEmpty()) {
            model.addAttribute("userList", userList);
        }
        return "user/findId_form";
    }

    @PostMapping("/sendVerificationCode")
    public String sendVerificationCode(@RequestParam("email") String email, Model model, HttpSession session) {
        String verificationCode = String.valueOf((int) (Math.random() * 9000) + 1000);

        try {
            List<User> members = this.userService.findIdByEmail(email);

            emailService.sendVerificationCode(email, verificationCode);
            session.setAttribute("userEmail", email);
            session.setAttribute("verificationCode", verificationCode);

            model.addAttribute("verificationCode", verificationCode);
            model.addAttribute("email", email);
            model.addAttribute("members", members);
            model.addAttribute("verificationCodeForm", true);
            model.addAttribute("showConfirmationScript", true);
        } catch (DataNotFoundException e) {
            model.addAttribute("notFound", true);
        }
        return "user/findId_form";
    }
    @GetMapping("/findIdPhone")
    public String findIdPhone() {
        return "user/findId_Phone";
    }

    @PostMapping("/findIdPhone")
    public String findIdPhone(@RequestParam("verificationCodeSMS") String verificationCodeSMS,
                              @RequestParam(value = "verificationCodeForm", required = false) boolean verificationCodeFormSMS,
                              Model model, HttpSession session) {
        // 세션에서 저장된 전화번호 가져오기
        String userPhone = (String) session.getAttribute("userPhone");
        String storedVerificationCodeSMS = (String) session.getAttribute("verificationCodeSMS");

        List<User> userList = this.userService.findIdByPhone(userPhone);

        model.addAttribute("verificationCodeMismatchSMS", false);
        model.addAttribute("verificationCodeFormSMS", verificationCodeFormSMS);
        model.addAttribute("phone", userPhone);

        if (verificationCodeSMS.equals(storedVerificationCodeSMS)) {
            model.addAttribute("userList", userList);
            model.addAttribute("verificationCodeFormSMS", true);
        }

        if (!verificationCodeSMS.equals(storedVerificationCodeSMS)) {
            // 인증 코드 불일치 처리 (예: 에러 메시지 전달)
            model.addAttribute("verificationCodeMismatchSMS", true);
            return "user/findId_Phone";
        }

        // 찾는 아이디 없을 때
        if (!userList.isEmpty()) {
            model.addAttribute("userList", userList);
        }
        return "user/findId_Phone";
    }
    @GetMapping("/sendVerificationCodeSign")
    public ResponseEntity<String> sendVerificationCodeSign(@RequestParam String phoneNumber, HttpSession session) {
        try {
            String storedVerificationCode = this.emailService.sendVerificationCodeSMS(phoneNumber);
//            String storedVerificationCode = this.smsService.sendMessage(phoneNumber);
            session.setAttribute("verificationCodeSMS", storedVerificationCode);
            return ResponseEntity.ok(storedVerificationCode); // Return the verification code
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error sending verification code");
        }
    }
    @PostMapping("/checkVerificationCode")
    public ResponseEntity<String> checkVerificationCode(@RequestParam String verificationNum, HttpSession session) {
        String storedVerificationCode = (String) session.getAttribute("verificationCodeSMS");

        if (storedVerificationCode != null && storedVerificationCode.equals(verificationNum)) {
            return ResponseEntity.ok("verified"); // 인증번호가 일치함을 클라이언트에 알림
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Verification code does not match"); // 인증번호가 일치하지 않음을 클라이언트에 알림
        }
    }
    @PostMapping("/sendVerificationCodeSMS")
    public String sendVerificationCodeSMS(@RequestParam("phone") String phone, Model model, HttpSession session) {
        try {
            List<User> userList = this.userService.findIdByPhone(phone);

            String verificationCodeSMS = this.emailService.sendVerificationCodeSMS(phone);

            // 세션에 이메일과 인증 코드 저장
            session.setAttribute("userPhone", phone);
            session.setAttribute("verificationCodeSMS", verificationCodeSMS);

            // 모델에 인증 코드 저장 (후에 확인을 위해)
            model.addAttribute("verificationCodeSMS", verificationCodeSMS);
            model.addAttribute("phone", phone);
            model.addAttribute("userList", userList);
            // 인증 코드 입력 폼을 보여주기 위해 "verificationCodeForm" 속성 추가
            model.addAttribute("verificationCodeFormSMS", true);
        } catch (DataNotFoundException e) {
            model.addAttribute("notFound1", true);
            model.addAttribute("errorMessage1", "휴대전화번호에 일치하는 아이디가 없습니다.");
        }
        // 휴대전화 입력 폼으로 리다이렉트
        return "user/findId_Phone";
    }

    @GetMapping("/findPassword")
    public String findPassword(@RequestParam(value = "resetSuccess", required = false) String resetSuccess,
                               Model model) {

        model.addAttribute("resetSuccess", resetSuccess);

        return "user/findPw_form";
    }

    @PostMapping("/findPassword")
    public String findPassword(@RequestParam("userId") String userId, Model model,
                               @RequestParam(name = "inputVerificationCode", defaultValue = "") String inputVerificationCode,
                               @RequestParam(name = "verificationCodeSent", defaultValue = "false") boolean verificationCodeSent,
                               @RequestParam(name = "verificationCode", defaultValue = "") String verificationCode,
                               HttpSession session) {
        try {
            User user = this.userService.getUser(userId);

            model.addAttribute("userId", userId);

            // 첫 시도 -> 인증코드 보낸 적 없음
            if (!verificationCodeSent) {
                String userEmail = user.getEmail();
                String temporaryPassword = this.userService.generateTemporaryPassword();
                emailService.sendVerificationCode(userEmail, temporaryPassword);
                model.addAttribute("verificationCode", temporaryPassword);
                model.addAttribute("verificationCodeSent", true);
                model.addAttribute("userEmail", userEmail); // 이메일 정보를 모델에 추가
                model.addAttribute("message", "임시번호가 이메일로 전송되었습니다.");

                // JavaScript로 확인 메시지를 보여주는 스크립트 추가
                model.addAttribute("showConfirmationScript", true);
                return "user/findPw_form";
            }

            boolean matched = verificationCode.equals(inputVerificationCode);

            if (matched) {
                model.addAttribute("verificationCodeValid", true);
                model.addAttribute("userEmail", user.getEmail()); // 여기에 userEmail 추가
            } else {
                model.addAttribute("message", "인증번호가 틀렸습니다.");
                model.addAttribute("verificationCodeValid", false);
                model.addAttribute("verificationCodeSent", true);
                model.addAttribute("verificationCode", verificationCode);
            }
            return "user/findPw_form";

        } catch (DataNotFoundException e) {
            model.addAttribute("message", "존재하지 않는 아이디입니다.");
            model.addAttribute("userId", userId);
        }

        return "user/findPw_form";
    }

    @PostMapping("/resendVerificationCode")
    private String resendVerificationCode(Model model, @RequestParam("userId") String userId) {

        User user = this.userService.getUser(userId);
        String userEmail = user.getEmail();

        String temporaryPassword = this.userService.generateTemporaryPassword();
        emailService.sendVerificationCode(userEmail, temporaryPassword);
        model.addAttribute("verificationCode", temporaryPassword);
        model.addAttribute("verificationCodeSent", true);
        model.addAttribute("userEmail", userEmail); // 이메일 정보를 모델에 추가
        model.addAttribute("userId", userId); // 이메일 정보를 모델에 추가


        model.addAttribute("showConfirmationScript", true);
        model.addAttribute("message", "인증번호 재전송 성공");

        return "user/findPw_form";
    }

    @GetMapping("/passwordReset")
    private String passwordReset(Model model) {
        model.addAttribute("verificationCode", "");
        model.addAttribute("newPassword", "");
        model.addAttribute("newPassword1", "");
        model.addAttribute("message", ""); // 메시지 초기화
        return "user/findPw_form";
    }

    @PostMapping("/passwordReset")
    public String passwordReset(@RequestParam("userId") String userId,
                                @RequestParam("verificationCode") String verificationCode,
                                @RequestParam("verificationCodeValid") String verificationCodeValid,
                                @RequestParam("newPassword") String newPassword,
                                @RequestParam("newPassword1") String newPassword1,
                                Model model) {

        System.out.println(userId);
        System.out.println(newPassword);
        System.out.println(newPassword1);
        System.out.println(verificationCodeValid);

        if (!newPassword.equals(newPassword1)) {
            // Passwords don't match
            model.addAttribute("verificationCode", verificationCode);
            model.addAttribute("verificationCodeValid", verificationCodeValid);
            model.addAttribute("newPassword", newPassword);
            model.addAttribute("newPassword1", newPassword1);
            model.addAttribute("userId", userId);
            return "user/findPw_form";
        }

        try {
            User user = this.userService.getUser(userId);
            this.userService.updatePassword(user, newPassword);
            model.addAttribute("message", "비밀번호가 재설정되었습니다.");
            return "redirect:/user/login";
        } catch (DataNotFoundException e) {
            // Handle if the user ID does not exist
            model.addAttribute("message", "존재하지 않는 아이디입니다.");
            return "user/findPw_form";
        } catch (Exception e) {
            // Handle other exceptions
            model.addAttribute("message", "비밀번호 업데이트에 실패했습니다.");
            return "user/findPw_form";
        }
    }
    @GetMapping("/findPasswordPhone")
    public String findPasswordPhone(@RequestParam(value = "resetSuccess", required = false) String resetSuccess, Model model) {

        model.addAttribute("resetSuccess", resetSuccess);

        return "user/findPw_Phone";
    }

    @PostMapping("/findPasswordPhone")//폰으로 비밀번호 찾기메서드 상당히 복잡하게 코드를짜서 좀 ㅠㅠ 변수명이 길어서 ㅠㅠ
    public String findPasswordPhone(@RequestParam("userId") String userId, Model model,
                                    @RequestParam(name = "inputVerificationCodePhone", defaultValue = "") String inputVerificationCodePhone,
                                    @RequestParam(name = "verificationCodeSentPhone", defaultValue = "false") boolean verificationCodeSentPhone,
                                    @RequestParam(name = "verificationCodePhone", defaultValue = "") String verificationCodePhone,
                                    HttpSession session) {
        try {
            User user = this.userService.getUser(userId);// 멤버서비스에서 아이디 정보가져오기

            model.addAttribute("userId", userId);//뷰로뿌려줘야하겠죠?

            // 첫 시도 -> 인증코드 보낸 적 없음
            if (!verificationCodeSentPhone) {
                String userPhone = user.getPhone();
                // 인증 코드 생성 (여기에서는 간단하게 난수로 생성)
//                String verificationCodeSMS = String.valueOf((int) (Math.random() * 9000) + 1000);
                String verificationCodeSMS = this.emailService.sendVerificationCodeSMS(userPhone);
//                smsService.sendMessage(userPhone, verificationCodeSMS);//sms서비스에서 인증번호 보내는 로직 가져와서 사용했습니다.
                model.addAttribute("verificationCodePhone", verificationCodeSMS);//임시비밀번호!!
                model.addAttribute("verificationCodeSentPhone", true);//임시비밀번호 첫번째폼
                model.addAttribute("userPhone", userPhone); // 폰 정보를 모델에 추가
                model.addAttribute("message", "임시번호가 휴대전화번호로 전송되었습니다.");
                // JavaScript로 확인 메시지를 보여주는 스크립트 추가
                model.addAttribute("showConfirmationScript", true);
                return "user/findPw_Phone";
            }

            boolean matched = verificationCodePhone.equals(inputVerificationCodePhone);

            if (matched) {
                model.addAttribute("verificationCodeValidPhone", true);//두번쨰 폼이 트루일때 조건
                model.addAttribute("userPhone", user.getPhone()); //폰 끌어와서 추가
            } else {
                model.addAttribute("message", "인증번호가 틀렸습니다.");
                model.addAttribute("verificationCodeValidPhone", false);
                model.addAttribute("verificationCodeSentPhone", true);
                model.addAttribute("verificationCodePhone", verificationCodePhone);
            }
            return "user/findPw_Phone";
        } catch (DataNotFoundException e) {
            model.addAttribute("message", "존재하지 않는 아이디입니다.");
            model.addAttribute("userId", userId);
        }
        return "user/findPw_Phone";
    }
    @PostMapping("/resendVerificationCodePhone")//폰인증번호 재전송 메서드
    private String resendVerificationCodePhone(Model model, @RequestParam("userId") String userId) {
        User user = this.userService.getUser(userId);

        String userPhone = user.getPhone();

        String verificationCodeSMS =  this.emailService.sendVerificationCodeSMS(userPhone);
//        smsService.sendMessage(userPhone, verificationCodeSMS);// 서비스에서 메세지 보내는거 끌어와주기
        model.addAttribute("verificationCodePhone", verificationCodeSMS);//인증코드
        model.addAttribute("verificationCodeSentPhone", true);//폼이 트루일때
        model.addAttribute("userPhone", userPhone); // 폰 정보를 모델에 추가
        model.addAttribute("userId", userId); //아이디정보를 모델에 추가


        model.addAttribute("showConfirmationScript", true);
        model.addAttribute("message", "인증번호 재전송 성공");

        return "user/findPw_Phone";
    }

    @PostMapping("/passwordResetPhone")//폰으로찾기해서 비밀번호 재설정하는 메서드
    public String passwordResetPhone(@RequestParam("userId") String userId,
                                     @RequestParam("verificationCodePhone") String verificationCodePhone,
                                     @RequestParam("verificationCodeValidPhone") String verificationCodeValidPhone,
                                     @RequestParam("newPassword") String newPassword,
                                     @RequestParam("newPassword1") String newPassword1,
                                     Model model) {
        if (!newPassword.equals(newPassword1)) {
            // 비밀번호 확인이 일치하지 않을 때
            model.addAttribute("verificationCode", verificationCodePhone);
            model.addAttribute("verificationCodeValidPhone", verificationCodeValidPhone);
            model.addAttribute("newPassword", newPassword);
            model.addAttribute("newPassword1", newPassword1);
            model.addAttribute("userId", userId);
            return "user/findPw_Phone";
        }
        try {
            User user = this.userService.getUser(userId);
            // 여기서 updatePassword 메서드를 호출할 때, 현재 비밀번호를 가진 Member 객체를 전달해야 합니다.
            User updateduser = this.userService.updatePassword(user, newPassword);
            model.addAttribute("message", "비밀번호가 재설정되었습니다.");

            // 비밀번호 재설정이 성공했을 때 alert를 띄우고 페이지를 이동
            return "redirect:/user/login";
        } catch (DataNotFoundException e) {
            // 존재하지 않는 아이디에 대한 예외 처리
            model.addAttribute("message", "존재하지 않는 아이디입니다.");
            return "user/findPw_Phone";
        } catch (Exception e) {
            // 기타 예외 처리
            model.addAttribute("message", "비밀번호 업데이트에 실패했습니다.");
            return "user/findPw_Phone";
        }
    }
}
