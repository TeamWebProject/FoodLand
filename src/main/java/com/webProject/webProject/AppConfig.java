package com.webProject.webProject;

import lombok.Getter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class AppConfig {
    @Bean
    public static String getImageFileDirPath() {
        // 원하는 경로로 지정해주세요
        return System.getProperty("user.dir") + "/src/main/resources/static/img/";
    }
}