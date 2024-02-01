package com.webProject.webProject.User.oAuth2;

import com.webProject.webProject.AppConfig;
import com.webProject.webProject.CustomUser;
import com.webProject.webProject.User.User;
import com.webProject.webProject.User.UserRepository;
import com.webProject.webProject.User.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SocialOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        String clientName = userRequest.getClientRegistration().getClientName();
        System.out.println("============" + clientName);
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        CustomUser customUser = null;

        if (clientName.equals("kakao")) {
            System.out.println("kakao");
        } else if (clientName.equals("Google")) {
            System.out.println("google");
        }

        if (clientName.equals("Google")) {
            String googleId = oAuth2User.getAttribute("sub");
            String email = oAuth2User.getAttribute("email");
            String nickname = oAuth2User.getAttribute("name");
            String picture = oAuth2User.getAttribute("picture");
            String img = saveImageFromUrl(nickname, clientName, picture);
            try {
                customUser = saveOrUpdateGoogle(googleId, email, nickname, img);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            System.out.println("Google User Saved: " + googleId + ", " + email + ", " + nickname);
        } else if (clientName.equals("kakao")) {
            System.out.println("Asdasd");
            Long kakaoId = oAuth2User.getAttribute("id");
            Map<String, Object> attributes = oAuth2User.getAttribute("properties");
            String nickname = (String) attributes.get("nickname");
            String picture = (String) attributes.get("profile_image");
            String img = saveImageFromUrl(nickname, clientName, picture);
            try {
                customUser = saveOrUpdateKakao(String.valueOf(kakaoId), nickname, img);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            System.out.println("Kakao User Saved: " + kakaoId + ", " + nickname);
        } else if (clientName.equals("Naver")) {
            Map<String, Object> attributes = oAuth2User.getAttribute("response");
            String naverId = (String) attributes.get("id");
            String email = (String) attributes.get("email");
            String name = (String)attributes.get("name");
            String picture = (String)attributes.get("profile_image");
            String img = saveImageFromUrl(name, clientName, picture);
            try {
                customUser = saveOrUpdateNaver(naverId, email, name, img);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            System.out.println("Naver User Saved: " + naverId + ", " + email + ", " + name);
        }
        return customUser;
    }

    //구글
    public CustomUser saveOrUpdateGoogle(String googleId, String email, String nickname, String img) throws IOException {
        String projectPath = AppConfig.getImageFileDirPath();;

        User user = this.userRepository.findByuserId(googleId).orElse(new User());
        String existingFilePath = user.getFilePath();

        // 기존 파일 삭제
        if (existingFilePath != null && !existingFilePath.isEmpty()) {
            java.nio.file.Path fileToDelete = java.nio.file.Paths.get(existingFilePath);
            try {
                java.nio.file.Files.delete(fileToDelete);
            } catch (IOException e) {
                System.out.println("기존 파일 삭제 실패: " + e.getMessage());
            }
        }

        user.setUserId(googleId);
        user.setEmail(email);
        user.setNickname(nickname);
        user.setRole("user");
        user.setCreateDate(LocalDateTime.now());
        user.setProvider("Google");
        user.setFileName(img); // 파일 이름
        user.setFilePath(projectPath + img); // 저장 경로, 파일 이름
        this.userRepository.save(user);

        List<GrantedAuthority> authorities = new ArrayList<>();
        if (user.getRole() != null && !user.getRole().isEmpty()) {
            if ("owner".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.OWNER.getValue()));
            } else if ("admin".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.getValue()));
            } else {
                authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue()));
            }
        }

        CustomUser customUser = new CustomUser(user.getUserId(), "", authorities);
        customUser.setNickname(user.getNickname());
        customUser.setRole(user.getRole());
        customUser.setFileName(user.getFileName());
        return customUser;
    }


    //카카오
    public CustomUser saveOrUpdateKakao(String kakaoId, String name, String img) throws IOException {
        String projectPath = AppConfig.getImageFileDirPath();;

        User user = this.userRepository.findByuserId(kakaoId).orElse(new User());
        String existingFilePath = user.getFilePath();

        // 기존 파일 삭제
        if (existingFilePath != null && !existingFilePath.isEmpty()) {
            java.nio.file.Path fileToDelete = java.nio.file.Paths.get(existingFilePath);
            try {
                java.nio.file.Files.delete(fileToDelete);
            } catch (IOException e) {
                System.out.println("기존 파일 삭제 실패: " + e.getMessage());
            }
        }
        user.setUserId(kakaoId);
        user.setNickname(name);
        user.setRole("user");
        user.setCreateDate(LocalDateTime.now());
        user.setProvider("Kakao");
        user.setFileName(img); // 파일 이름
        user.setFilePath(projectPath + img); // 저장 경로, 파일 이름
        this.userRepository.save(user);

        List<GrantedAuthority> authorities = new ArrayList<>();
        if (user.getRole() != null && !user.getRole().isEmpty()) {
            if ("owner".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.OWNER.getValue()));
            } else if ("admin".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.getValue()));
            } else {
                authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue()));
            }
        }

        CustomUser customUser = new CustomUser(user.getUserId(), "", authorities);
        customUser.setNickname(user.getNickname());
        customUser.setRole(user.getRole());
        customUser.setFileName(user.getFileName());
        return customUser;
    }

    //네이버
    public CustomUser saveOrUpdateNaver(String naverId, String email, String nickname, String img) throws IOException {
        String projectPath = AppConfig.getImageFileDirPath();;

        User user = this.userRepository.findByuserId(naverId).orElse(new User());
        String existingFilePath = user.getFilePath();

        // 기존 파일 삭제
        if (existingFilePath != null && !existingFilePath.isEmpty()) {
            java.nio.file.Path fileToDelete = java.nio.file.Paths.get(existingFilePath);
            try {
                java.nio.file.Files.delete(fileToDelete);
            } catch (IOException e) {
                System.out.println("기존 파일 삭제 실패: " + e.getMessage());
            }
        }
        user.setUserId(naverId);
        user.setEmail(email);
        user.setNickname(nickname);
        user.setRole("user");
        user.setCreateDate(LocalDateTime.now());
        user.setProvider("Naver");
        user.setFileName(img); // 파일 이름
        user.setFilePath(projectPath + img); // 저장 경로, 파일 이름
        this.userRepository.save(user);

        List<GrantedAuthority> authorities = new ArrayList<>();
        if (user.getRole() != null && !user.getRole().isEmpty()) {
            if ("owner".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.OWNER.getValue()));
            } else if ("admin".equals(user.getRole())) {
                authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.getValue()));
            } else {
                authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue()));
            }
        }

        CustomUser customUser = new CustomUser(user.getUserId(), "", authorities);
        customUser.setNickname(user.getNickname());
        customUser.setRole(user.getRole());
        customUser.setFileName(user.getFileName());
        return customUser;    }


    public String saveImageFromUrl(String nickname, String clientName, String imageUrl) {
        UUID uuid = UUID.randomUUID(); // 식별자. 랜덤으로 이름 생성
        String imageName = uuid + "_" + clientName + "_" + nickname + "_img.jpg"; // 이미지 파일명
        String staticImagesDirectory = AppConfig.getImageFileDirPath();;
        try {
            URL url = new URL(imageUrl);
            ReadableByteChannel readableByteChannel = Channels.newChannel(url.openStream());
            String filePath = staticImagesDirectory + File.separator + imageName;
            FileOutputStream fileOutputStream = new FileOutputStream(filePath);
            FileChannel fileChannel = fileOutputStream.getChannel();
            fileChannel.transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
            fileOutputStream.close();
            fileChannel.close();
            readableByteChannel.close();
            System.out.println("이미지 다운로드 완료: " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return imageName;
    }
}
