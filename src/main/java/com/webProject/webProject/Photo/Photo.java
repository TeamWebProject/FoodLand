package com.webProject.webProject.Photo;

import com.webProject.webProject.Menu.Menu;
import com.webProject.webProject.Review.Review;
import com.webProject.webProject.Store.Store;
import groovyjarjarpicocli.CommandLine;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Photo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToOne
    private Review review;

    @ManyToOne
    private Store store;

    @ManyToOne
    private Menu menu;

    @Column(columnDefinition = "TEXT NOT NULL")
    private String fileName;  // 파일 원본명

    @Column(columnDefinition = "TEXT NOT NULL")
    private String filePath;  // 파일 저장 경로


}
