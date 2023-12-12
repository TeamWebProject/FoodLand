package com.webProject.webProject.Photo;

import com.webProject.webProject.Menu.Menu;
import com.webProject.webProject.Review.Review;
import com.webProject.webProject.Review.ReviewRepository;
import com.webProject.webProject.Review_tag.Review_tag;
import com.webProject.webProject.Store.Store;
import com.webProject.webProject.Tag.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PhotoService {
    private final PhotoRepository photoRepository;

    @Value("${ImgLocation}")
    public String imgLocation;

    public void saveImgsForReview(Review review, List<MultipartFile> files) throws Exception {
        if (review != null && files != null && !files.isEmpty()) {
            for (MultipartFile file : files) {
                if (!file.isEmpty()) {
                    String projectPath = imgLocation;
                    UUID uuid = UUID.randomUUID();
                    String fileName = uuid + "_" + file.getOriginalFilename();
                    File saveFile = new File(projectPath, fileName);
                    file.transferTo(saveFile);

                    Photo photo = new Photo();
                    photo.setFileName(fileName);
                    photo.setFilePath(saveFile.getAbsolutePath());
                    photo.setReview(review);

                    this.photoRepository.save(photo);
                }
            }
        }
    }

    public void deletePhotosByReview(Review review) {
        List<Photo> photos = review.getPhotoList();

        if (photos != null && !photos.isEmpty()) {
            for (Photo photo : new ArrayList<>(photos)) {
                File imageFile = new File(photo.getFilePath());
                if (imageFile.exists()) {
                    imageFile.delete();
                }
                this.photoRepository.delete(photo);
                photos.remove(photo);
            }
        }
    }
//--------------------------------------------------------------------------------------------------------
    public void saveImgsForStore(Store store, List<MultipartFile> files) throws Exception {
        if (store != null && files != null && !files.isEmpty()) {
            for (MultipartFile file : files) {
                if (!file.isEmpty()) {
                    String projectPath = imgLocation;
                    UUID uuid = UUID.randomUUID();
                    String fileName = uuid + "_" + file.getOriginalFilename();
                    File saveFile = new File(projectPath, fileName);
                    file.transferTo(saveFile);

                    Photo photo = new Photo();
                    photo.setFileName(fileName);
                    photo.setFilePath(saveFile.getAbsolutePath());
                    photo.setStore(store);

                    this.photoRepository.save(photo);
                }
            }
        }
    }

    public void deletephotoById(Integer photoid) {
        this.photoRepository.delete(photoRepository.findById(photoid).get());
    }

    public void deletePhotosByStore(Store store) {
        List<Photo> photos = store.getPhotoList();

        if (photos != null && !photos.isEmpty()) {
            for (Photo photo : new ArrayList<>(photos)) {
                File imageFile = new File(photo.getFilePath());
                if (imageFile.exists()) {
                    imageFile.delete();
                }
                this.photoRepository.delete(photo);
                photos.remove(photo);
            }
        }
    }

    public Photo getStoreById(Integer id) {
        return this.photoRepository.findStoreById(id);
    }

    public void saveImgsForMenu(Menu menu, List<MultipartFile> files) throws Exception {
        if (menu != null && files != null && !files.isEmpty()) {
            String projectPath = imgLocation;

            for (MultipartFile file : files) {
                if (!file.isEmpty()) {
                    UUID uuid = UUID.randomUUID();
                    String fileName = uuid + "_" + file.getOriginalFilename();
                    File saveFile = new File(projectPath, fileName);

                    if (saveFile.exists() && saveFile.isFile()) {
                        saveFile.delete();
                    }

                    // Transfer the new file to the specified path
                    file.transferTo(saveFile);

                    // Save the information to the database
                    Photo photo = new Photo();
                    photo.setFileName(fileName);
                    photo.setFilePath(saveFile.getAbsolutePath());
                    photo.setMenu(menu);

                    this.photoRepository.save(photo);
                }
            }
        }
    }


    public void savedefaultImgsForMenu(Menu menu, List<MultipartFile> files) throws IOException {
        String projectPath = imgLocation;
        String fileName = "no_img.jpg";

        if (files == null || files.isEmpty() || (files.size() == 1 && files.get(0).getOriginalFilename().isEmpty())) {
            File defaultImageFile = new File(projectPath, fileName);

            if (!defaultImageFile.exists()) {
                ClassPathResource defaultImageResource = new ClassPathResource("static/no_img.jpg");
                Files.copy(defaultImageResource.getInputStream(), defaultImageFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }

            String filePath = Paths.get(projectPath, fileName).toString();

            if (defaultImageFile.exists()) {
                Photo defaultPhoto = new Photo();
                defaultPhoto.setFileName(fileName);
                defaultPhoto.setFilePath(filePath);
                defaultPhoto.setMenu(menu);

                this.photoRepository.save(defaultPhoto);
            }
        }
    }

    public void deleteMenuImage(Menu menu) {
        List<Photo> photos = menu.getPhotoList();

        if (photos != null && !photos.isEmpty()) {
            for (Photo photo : new ArrayList<>(photos)) {
                File imageFile = new File(photo.getFilePath());
                if (imageFile.exists()) {
                    imageFile.delete();
                }
                this.photoRepository.delete(photo);
                photos.remove(photo);
            }
        }
    }

}
