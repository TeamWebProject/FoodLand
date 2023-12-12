package com.webProject.webProject.User;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Setter
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private String userId;

    private String password;

    private String email;

    private String nickname;

    private String role; // 권한 (admin, owner, user)

    private LocalDateTime createDate;

    private LocalDateTime modifyDate;

    private String fileName;  // 파일 원본명

    private String filePath;  // 파일 저장 경로

    private String provider;

    private String phone;
}
