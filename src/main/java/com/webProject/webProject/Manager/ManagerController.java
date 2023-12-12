package com.webProject.webProject.Manager;

import com.webProject.webProject.Comment.Comment;
import com.webProject.webProject.Comment.CommentService;
import com.webProject.webProject.Photo.PhotoService;
import com.webProject.webProject.Review.Review;
import com.webProject.webProject.Review.ReviewService;
import com.webProject.webProject.Review_tag.Review_tagService;
import com.webProject.webProject.Store.Store;
import com.webProject.webProject.Store.StoreService;
import com.webProject.webProject.User.User;
import com.webProject.webProject.User.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/manager")
@RequiredArgsConstructor
public class ManagerController {
    private final StoreService storeService;
    private final UserService userService;
    private final ReviewService reviewService;
    private final CommentService commentService;
    private final PhotoService photoService;
    private final Review_tagService reviewTagService;

    @GetMapping("/member")
    public String memberlist(Model model, @RequestParam(value="page", defaultValue="0") int page, @RequestParam(value = "kw", defaultValue = "") String kw){
        String role = "user";
        Page<User> paging = this.userService.getList(page, kw, role);
        model.addAttribute("paging", paging);
        model.addAttribute("kw", kw);
        return "manager/manager_userList";
    }

    @GetMapping("/member/delete/{id}")
    public String memberDelete(@PathVariable("id") String id) {
        User user = this.userService.getUser(id);
        this.reviewService.deleteReviewsByUser(user);
        this.userService.delete(user);
        return "redirect:/manager/member";
    }




    @GetMapping("/owner")
    public String ownerlist(Model model, @RequestParam(value="page", defaultValue="0") int page, @RequestParam(value = "kw", defaultValue = "") String kw){
        String role = "owner";
        Page<User> paging = this.userService.getList(page, kw, role);
        model.addAttribute("paging", paging);
        model.addAttribute("kw", kw);
        return "manager/manager_ownerList";
    }

    @GetMapping("/store")
    public String storelist(Model model,  @RequestParam(value="page", defaultValue="0") int page, @RequestParam(value = "kw", defaultValue = "") String kw){
        Page<Store> paging = this.storeService.getList(page, kw);
        model.addAttribute("paging", paging);
        return "manager/manager_storeList";
    }
    @GetMapping("/store/delete/{id}")
    public String storedelete(@PathVariable("id") Integer id){
        Store store = this.storeService.getStore(id);
        this.storeService.deleteStore(store);
        return "redirect:/manager/store";
    }

    @GetMapping("/review/{id}")
    public String reviewlist(Model model, @PathVariable("id") Integer id) {
        Store store = storeService.getStore(id);
        List<Review> reviewList = this.reviewService.getreviewList(store);
        model.addAttribute("reviewList", reviewList);
        return "manager/manager_reviewList";
    }

    @GetMapping("/review/delete/{id}")
    public String reviewdelete(@PathVariable("id") Integer id) {
        Review review = this.reviewService.getReview(id);
        List<Comment> commentsToDelete = review.getCommentList();
        for (Comment comment : commentsToDelete) {
            this.commentService.delete(comment);
        }
        this.photoService.deletePhotosByReview(review);
        this.reviewTagService.deleteTagsByReviewId(id);
        this.reviewService.delete(review);
        return String.format("redirect:/manager/review/%s", review.getStore().getId());
    }
}
