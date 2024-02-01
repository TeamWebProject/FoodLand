package com.webProject.webProject.Tag;

import com.webProject.webProject.DataNotFoundException;
import com.webProject.webProject.Store.Store;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TagService {
    private final TagRepository tagRepository;
    public Tag getTagById(Integer tag) {
        Optional<Tag> Tag = this.tagRepository.findById(tag);
        if (Tag.isPresent()) {
            return Tag.get();
        } else {
            throw new DataNotFoundException("Tag not found");
        }
    }

    public List<Tag> getAllTags() {
        return this.tagRepository.findAll();
    }

    @PostConstruct
    public void init() {
        saveDefaultTag();
    }

    public void saveDefaultTag() {
        if (tagRepository.findBytagName("음식이 맛있어요") == null) {
            Tag tag = new Tag();
            tag.setTagName("음식이 맛있어요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("친절해요") == null) {
            Tag tag = new Tag();
            tag.setTagName("친절해요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("재료가 신선해요") == null) {
            Tag tag = new Tag();
            tag.setTagName("재료가 신선해요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("양이 많아요") == null) {
            Tag tag = new Tag();
            tag.setTagName("양이 많아요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("매장이 청결해요") == null) {
            Tag tag = new Tag();
            tag.setTagName("매장이 청결해요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("가성비가 좋아요") == null) {
            Tag tag = new Tag();
            tag.setTagName("가성비가 좋아요");
            tagRepository.save(tag);
        }
        if (tagRepository.findBytagName("혼밥하기 좋아요") == null) {
            Tag tag = new Tag();
            tag.setTagName("혼밥하기 좋아요");
            tagRepository.save(tag);
        }
    }
}
