package com.webProject.webProject.Store;

import com.webProject.webProject.DataNotFoundException;
import com.webProject.webProject.Photo.Photo;
import com.webProject.webProject.User.User;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.awt.print.PageFormat;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class StoreService {

    private final StoreRepository storeRepository;
    private List<MultipartFile> files;

    public Store createStore(User user, String name, String content, String category, String roadAddress, String jibunAddress) {
        Store store = new Store();
        store.setAuthor(user);
        store.setName(name);
        store.setContent(content);
        store.setCategory(category);
        store.setRoadAddress(roadAddress);
        store.setJibunAddress(jibunAddress);
        store.setCreateDate(LocalDateTime.now());
        return this.storeRepository.save(store);
    }


    public Store getStore(Integer id) {
        Optional<Store> store = this.storeRepository.findById(id);
        if (store.isPresent()) {
            return store.get();
        } else {
            throw new DataNotFoundException("store not found");
        }
    }

    public String getLocationFromCoordinates(String latitude, String longitude) {
        // 여기서는 가정적으로 위도와 경도를 사용하여 위치 정보를 반환하는 방식을 작성합니다.
        // 실제로는 외부 API를 호출하여 해당 위도와 경도에 대한 위치 정보를 가져와야 합니다.

        // 예시로 위도와 경도를 합쳐서 위치 정보를 생성하는 방식을 사용합니다.
        String location = "위도: " + latitude + ", 경도: " + longitude;

        return location;
    }
    public Store findstoreById(Integer id) {
        return this.storeRepository.findById(id).get();
    }


    public void modifyStore(Store store, String name, String content, String category, String postcode, String roadAddress, String jibunAddress) {
        store.setName(name);
        store.setContent(content);
        store.setCategory(category);
        store.setPostcode(postcode);
        store.setRoadAddress(roadAddress);
        store.setJibunAddress(jibunAddress);
        this.storeRepository.save(store);
    }

    public void deleteStore(Store store) {
        // Menu 객체에서 Photo 리스트를 가져옴
        List<Photo> photoList = store.getPhotoList();

        // 각 Photo 객체에 대해 파일 삭제 수행
        for (Photo photo : photoList) {
            // Photo 클래스에 파일 경로를 가져올 수 있는 메서드가 있다고 가정
            String filePath = photo.getFilePath();

            // 파일 경로가 있다면 파일을 삭제
            if (filePath != null && !filePath.isEmpty()) {
                deleteExistingFile(filePath);
            }
        }
        this.storeRepository.delete(store);
    }

    public List<Store> getAddressList(String jibunAddress) {
        String[] addressParts = jibunAddress.split("\\s+"); // 공백을 기준으로 문자열 분할
        String formattedAddress = String.join(" ", Arrays.copyOfRange(addressParts, 0, 3)); // 처음 세 부분을 결합

        Specification<Store> spec = search(formattedAddress); // 형식화된 주소 사용
        return this.storeRepository.findAllByKeyword(formattedAddress);
    }

    private Specification<Store> search(String kw) {
        return new Specification<>() {
            private static final long serialVersionUID = 1L;
            @Override
            public Predicate toPredicate(Root<Store> q, CriteriaQuery<?> query, CriteriaBuilder cb) {
                query.distinct(true);  // 중복을 제거
                return cb.like(q.get("jibunAddress"), "%" + kw + "%"); // 제목
            }
        };
    }

    public Page<Store> getownerList(int page, User owner) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("createDate"));
        Pageable pageable = PageRequest.of(page,9, Sort.by(sorts));
        return this.storeRepository.findAllByownerId(owner.getNickname(), pageable);
    }


    public Page<Store> getList(int page, String kw) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("createDate"));
        Pageable pageable = PageRequest.of(page, 9, Sort.by(sorts));
        return this.storeRepository.findStoreByKeyword(kw, pageable);
    }

    public Page<Store> searchownerStoreList(int page, String keyword) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("createDate"));
        Pageable pageable = PageRequest.of(page, 9, Sort.by(sorts));
        return this.storeRepository.findownerStoresByKeyword(keyword, pageable);
    }



    public boolean deleteExistingFile(String existingFilePath) {
        if (existingFilePath != null && !existingFilePath.isEmpty()) {
            File existingFile = new File(existingFilePath);
            if (existingFile.exists()) {
                // 파일 삭제 작업이 성공하면 true 반환
                return existingFile.delete();
            }
        }
        return false;
    }
}
