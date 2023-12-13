package com.webProject.webProject.Comment;

import com.webProject.webProject.Review.Review;
import com.webProject.webProject.Review.ReviewService;
import com.webProject.webProject.User.User;
import com.webProject.webProject.User.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;

@Controller
@RequestMapping("/comment")
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;
    private final ReviewService reviewService;
    private final UserService userService;

    @PreAuthorize("isAuthenticated()")
    @GetMapping(value = "/create/review/{id}")
    public String createReviewComment(CommentForm commentForm) {
        return "comment/comment_form";
    }

    // 질문에 대한 코멘트
    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/create/review/{id}")
    public String createQuestionComment(Model model, @PathVariable("id") Integer id, @Valid CommentForm commentForm,
                                        BindingResult bindingResult, Principal principal) {
        Review review = this.reviewService.getReview(id);
        User user = this.userService.getUser(principal.getName());
        if (bindingResult.hasErrors()) {
            model.addAttribute("review", review);
            return "store/store_detail";
        }

        Comment comment = this.commentService.create(review, commentForm.getContent(), user);
        return String.format("redirect:/store/detail/%s#comment_%s", comment.getReview().getStore().getId(), comment.getId());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/modify/{id}")
    public String modifyComment(CommentForm commentForm, @PathVariable("id") Integer id, Principal principal) {
        Comment comment = this.commentService.getComment(id);
        if (!comment.getAuthor().getUserId().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정 권한이 없습니다.");
        }
        commentForm.setContent(comment.getContent());
        return "comment/comment_form";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/modify/{id}")
    public String modifyComment(@Valid CommentForm commentForm, BindingResult bindingResult, Principal principal,
                                @PathVariable("id") Integer id) {
        if (bindingResult.hasErrors()) {
            return "comment/comment_form";
        }
        Comment comment = this.commentService.getComment(id);
        if (!comment.getAuthor().getUserId().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정 권한이 없습니다.");

        }
        this.commentService.modify(comment, commentForm.getContent());
        return String.format("redirect:/store/detail/%s", comment.getReview().getStore().getId());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/delete/{id}")
    public String deleteComment(Principal principal, @PathVariable("id") Integer id) {
        Comment comment = this.commentService.getComment(id);
        if (!comment.getAuthor().getUserId().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "삭제 권한이 없습니다.");
        }
        this.commentService.delete(comment);
        return String.format("redirect:/store/detail/%s", comment.getReview().getStore().getId());
    }

}