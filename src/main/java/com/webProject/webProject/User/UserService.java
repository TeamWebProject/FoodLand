package com.webProject.webProject.User;

import com.webProject.webProject.AppConfig;
import com.webProject.webProject.DataNotFoundException;
import com.webProject.webProject.Tag.Tag;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public List<User> getUserList() {
        return this.userRepository.findAll();
    }

    public User create(String userId, String email, String password, String nickname, String role, String phone, MultipartFile file) throws Exception {
        String projectPath = AppConfig.getImageFileDirPath();; // 파일 저장 위치 = projectPath
        //C:/Users/admin/Desktop/web_project/src/main/resources/static/img/
        UUID uuid = UUID.randomUUID(); // 식별자. 랜덤으로 이름 생성
        String fileName;

        if (file == null || file.isEmpty()) {
            fileName = "no_img.jpg"; // 기본 이미지 파일명
            File defaultImageFile = new File(projectPath, fileName);

            // 기본 이미지를 static 폴더에서 복사
            ClassPathResource defaultImageResource = new ClassPathResource("static/no_img.jpg");
            Files.copy(defaultImageResource.getInputStream(), defaultImageFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } else {
            fileName = uuid + "_" + file.getOriginalFilename(); // 저장될 파일 이름 지정 = 랜덤 식별자_원래 파일 이름
            File saveFile = new File(projectPath, fileName); // 빈 껍데기 생성, 이름은 fileName, projectPath라는 경로에 담김
            file.transferTo(saveFile);
        }

        User user = new User();
        user.setUserId(userId);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setNickname(nickname);
        user.setRole(role);
        user.setPhone(phone);
        user.setCreateDate(LocalDateTime.now());
        user.setProvider("web");  // 홈페이지에서 회원가입했을시 -> 소셜로그인 X
        user.setFileName(fileName); // 파일 이름
        user.setFilePath(projectPath + fileName); // 저장 경로, 파일 이름

        this.userRepository.save(user);
        return user;
    }


    public User getUser(String userId) {
        Optional<User> user = this.userRepository.findByuserId(userId);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new DataNotFoundException("user not found");
        }
    }

    public User modify(User user, String nickname, String email, MultipartFile file) throws IOException {
        String projectPath = AppConfig.getImageFileDirPath();;
        String existingFilePath = user.getFilePath();

        if (file != null && !file.isEmpty()) {
            deleteExistingFile(existingFilePath);

            String fileName = uploadFile(file, projectPath);
            user.setFileName(fileName);
            user.setFilePath(projectPath + File.separator + fileName);
        }

        // 사용자 정보 업데이트
        user.setNickname(nickname);
        user.setEmail(email);
        return userRepository.save(user);
    }

    public boolean deleteExistingFile(String existingFilePath) {
        if (existingFilePath != null && !existingFilePath.isEmpty()) {
            File existingFile = new File(existingFilePath);
            if (existingFile.exists()) {
                existingFile.delete();
            }
        }
        return false;
    }

    public String uploadFile(MultipartFile file, String projectPath) throws IOException {
        if (file != null && !file.isEmpty()) {
            UUID uuid = UUID.randomUUID();
            String fileName = uuid + "_" + file.getOriginalFilename();
            File saveFile = new File(projectPath, fileName);
            file.transferTo(saveFile);
            return fileName;
        }
        return null;
    }

    public void modifyPw(User user, String pw) {
        user.setPassword(passwordEncoder.encode(pw));
        user.setModifyDate(LocalDateTime.now());
        this.userRepository.save(user);
    }

    public List<User> getOwnerListByRole(String role) {
        return this.userRepository.findByRole(role);
    }

    public List<User> getUserListByRole(String role) {
        return this.userRepository.findByRole(role);
    }

    public void delete(User user) {
        this.userRepository.delete(user);
    }

    public Page<User> getList(int page, String kw, String role) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("createDate"));
        Pageable pageable = PageRequest.of(page, 6, Sort.by(sorts));
        return this.userRepository.findAllByRoleAndNicknameContaining(role, kw, pageable);
    }

    public List<User> findIdByEmail(String email) {
        return this.userRepository.findByEmail(email);
    }

    public String generateTemporaryPassword() {
        // 임시 비밀번호를 랜덤으로 생성 (이 부분을 보안적으로 강화할 수 있음)
        int length = 10;
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder temporaryPassword = new StringBuilder();

        Random random = new Random();
        for (int i = 0; i < length; i++) {
            temporaryPassword.append(characters.charAt(random.nextInt(characters.length())));
        }

        return temporaryPassword.toString();
    }

    public User updatePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(user);
    }

    public List<User> findIdByPhone(String userPhone) {
        return this.userRepository.findByPhone(userPhone);
    }

    @PostConstruct
    public void init() {
        saveDefaultAdmin();
    }

    public void saveDefaultAdmin() {
        if (userRepository.findByrole("admin") == null) {
            User user = new User();
            user.setUserId("admin");
            user.setPassword(passwordEncoder.encode("1234"));
            user.setNickname("관리자");
            user.setEmail("admin@naver.com");
            user.setRole("admin");
            user.setCreateDate(LocalDateTime.now());
            user.setPhone("01011112222");
            userRepository.save(user);
        }
    }
}
