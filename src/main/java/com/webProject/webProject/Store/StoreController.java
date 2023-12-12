package com.webProject.webProject.Store;


import com.webProject.webProject.CustomUser;
import com.webProject.webProject.Menu.Menu;
import com.webProject.webProject.Menu.MenuForm;
import com.webProject.webProject.Menu.MenuFormWrapper;

import com.webProject.webProject.Menu.MenuService;
import com.webProject.webProject.Photo.Photo;
import com.webProject.webProject.Photo.PhotoService;
import com.webProject.webProject.Review.Review;
import com.webProject.webProject.Review.ReviewService;
import com.webProject.webProject.Review_tag.Review_tag;
import com.webProject.webProject.Review_tag.Review_tagRepository;
import com.webProject.webProject.Tag.Tag;
import com.webProject.webProject.User.User;
import com.webProject.webProject.User.UserSecurityService;
import com.webProject.webProject.User.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.w3c.dom.ls.LSException;

import java.security.Principal;
import java.util.*;

@Controller
@RequestMapping("/store")
@RequiredArgsConstructor
public class StoreController {
    private final StoreService storeService;
    private final UserService userService;
    private final ReviewService reviewService;
    private final PhotoService photoService;
    private final MenuService menuService;
    private final UserSecurityService userSecurityService;
    private final StoreRepository storeRepository;

    Store tempStore = new Store();
    List<Menu> tempmenuList = new ArrayList<>();


    @RequestMapping("/list")
    public String list(Model model, @RequestParam(value = "address", required = false) String jibunAddress) {        // required = false 초기값 공백
        List<Store> storeList  = this.storeService.getAddressList(jibunAddress);
        model.addAttribute("location", jibunAddress);
        model.addAttribute("storeList", storeList);
        return "store/store_list";
    }

    @RequestMapping("/findlist")
    public String find_list(Model model, @RequestParam(value = "findAddress", required = false) String jibunAddress) {
        List<Store> storeList  = this.storeService.getAddressList(jibunAddress);
        System.out.println(jibunAddress);
        model.addAttribute("location", jibunAddress);
        model.addAttribute("storeList", storeList);
        return "store/store_list";
    }


    @GetMapping("/detail/{id}") // 해당 id는 store id
    public String detail(Model model, @PathVariable("id") Integer id) {
        Store store = this.storeService.getStore(id);
        List<Review> reviewList = this.reviewService.getreviewList(store);
        List<Menu> menuList = this.menuService.getstoreMenu(store);

        if (!reviewList.isEmpty()) {
            for (Review review : reviewList) {
                List<Review_tag> tagList = review.getReviewTagList();
                review.setReviewTagList(tagList);
            }
            Review firstReview = reviewList.get(0);
            model.addAttribute("review", firstReview);
        } else {
            Review emptyReview = new Review();
            model.addAttribute("review", emptyReview);
        }

        model.addAttribute("menuList", menuList);
        model.addAttribute("reviewList", reviewList);
        model.addAttribute("store", store);
        return "store/store_detail";
    }
    //------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/create")
    public String createStore(StoreForm storeForm,Principal principal, Model model){
        return "store/store_form";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/create")
    public String createStore(Model model, StoreForm storeForm, BindingResult bindingResult, Principal principal, List<MultipartFile> fileList) throws Exception{
        User user = this.userService.getUser(principal.getName());

        if (bindingResult.hasErrors()) {
            return "store/store_owner_list";
        }
        Store newStore = storeService.createStore(user, storeForm.getName(),storeForm.getContent(),storeForm.getCategory(),storeForm.getRoadAddress(), storeForm.getJibunAddress());
        menuService.saveMenus(newStore,tempmenuList);
        newStore.setMenuList(tempmenuList);
        photoService.saveImgsForStore(newStore, fileList);
        tempmenuList.clear();
        return "redirect:/store/owner/list";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/owner/list")
    public String ownerpage_list(Model model,Principal principal, @RequestParam(value ="page", defaultValue = "0")int page) {

        if (principal == null ) {
            return "redirect:/user/login";
        } else {
            User siteUser = this.userService.getUser(principal.getName());
            Page<Store> paging = this.storeService.getownerList(page, siteUser);
            model.addAttribute("paging",paging);
            return "store/store_owner_list";
        }
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/modify/{storeid}")
    public String modifystore(Model model, StoreForm storeForm, @PathVariable("storeid")Integer id ,Principal principal) {
        Store store = storeService.findstoreById(id);
        storeForm.setName(store.getName());
        storeForm.setContent(store.getContent());
        storeForm.setCategory(store.getCategory());
        storeForm.setPostcode(store.getPostcode());
        storeForm.setRoadAddress(store.getRoadAddress());
        storeForm.setJibunAddress(store.getJibunAddress());
        storeForm.setMenuList(store.getMenuList());

        model.addAttribute("store",store);
        model.addAttribute("process", "modify/"+ store.getId());
        return "store/store_form";
    }
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/modify/{storeid}")
    public String modifystore(StoreForm storeForm ,@PathVariable("storeid")Integer id, BindingResult bindingResult, List<MultipartFile> fileList, Principal principal) throws Exception{
        Store store = storeService.findstoreById(id);
        int anchor = id;

        photoService.saveImgsForStore(store, fileList);


        List<MultipartFile> newPhotos = storeForm.getFileList();
//        this.photoService.deletePhotosByStore(store);//수정안할수도있는데 지워버리면..;;

        if (newPhotos!= null && !newPhotos.isEmpty()) {
            this.photoService.saveImgsForStore(store, newPhotos);
        }

        menuService.saveMenus(store,tempmenuList);
        store.setMenuList(tempmenuList);
        this.storeService.modifyStore(store, storeForm.getName(), storeForm.getContent(), storeForm.getCategory(), storeForm.getPostcode(), storeForm.getRoadAddress(), storeForm.getJibunAddress());
        tempmenuList.clear();
//        return String.format("redirect:/store/owner/list/#store_%s", anchor);
        return "redirect:/store/owner/list";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/delete/{storeid}")
    public String deletestore(@PathVariable("storeid")Integer id,Principal principal) {
//        int anchor = id-1;
        Store store = this.storeService.getStore(id);
        storeService.deleteStore(store);
        return "redirect:/store/owner/list";
//        return String.format("redirect:/store/owner/list/#%s", anchor);
    }

//====================가게사진 수정, 삭제, 저장============================
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/updatephoto/{storeid}")
    public String addphoto(@PathVariable("storeid")Integer storeid, Model model) {
        Store store = storeService.findstoreById(storeid);

        model.addAttribute("store",store);
        return "store/store_photo";
    }
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/deletephoto")
    public String deletephoto(Integer photoid, Integer storeid) {
        photoService.deletephotoById(photoid);
        return "redirect:/store/updatephoto/"+ storeid;
    }
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/savephoto")
    public String savephoto(Integer storeid, List<MultipartFile> fileList) throws Exception {
        photoService.saveImgsForStore(storeService.findstoreById(storeid), fileList);
        return "redirect:/store/updatephoto/"+ storeid;
    }

//=============================================================================


    @PreAuthorize("isAuthenticated()")
    @GetMapping("/menuList/{storeid}")
    public String menuList(@PathVariable(name = "storeid") Integer storeid, Model model) {
        Store store = storeService.findstoreById(storeid);
        List<Menu> menuList = menuService.getstoreMenu(store);
        model.addAttribute("menuList", menuList);
        model.addAttribute("store",store);
        return "menu/menu_list";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/owner/search_list")
    public String owner_storesearch(Principal principal, String keyword, Model model, @RequestParam(value ="page", defaultValue = "0")int page) {
        if (principal == null ) {
            return "redirect:/user/login";
        } else {
            Page<Store> paging = this.storeService.getList(page, keyword);
            model.addAttribute("paging",paging);
            return "store/store_owner_list";
        }
    }


    @PostMapping("/search_list")
    public String search_list(Model model, String keyword) {//, @RequestParam(value = "findAddress", required = false) String jibunAddress
        System.out.println(keyword);
        List<Store> storeList = this.storeService.searchStoreList(keyword);
//        List<Store> storeList  = this.storeService.getAddressList(jibunAddress);
//        System.out.println(jibunAddress);
        model.addAttribute("location", "대전");
        model.addAttribute("storeList", storeList);
        return "store/store_list";
    }

    @PostMapping("/search_list_menu")
    public String search_list_menu(Model model, String keyword) {//, @RequestParam(value = "findAddress", required = false) String jibunAddress
        List<Menu> menuList = this.menuService.searchedmenu_storelist(keyword);

        List<Integer> storeid = new ArrayList<>();

        List<Store> storeList = new ArrayList<>();

        for (Menu menu : menuList) {
            storeList.add(storeService.findstoreById(menu.getStore().getId()));
        }
        for (Store store:storeList) {
            storeid.add(store.getId());
        }

        Set<Integer> set = new HashSet<Integer>(storeid);
        List<Integer> newstoreid = new ArrayList<Integer>(set); //중복된거 없앤 가게 아이디 리스트..

        List<Store> newstoreList = new ArrayList<>();
        for (Integer id : newstoreid) {
            newstoreList.add(storeService.findstoreById(id));
        }

        model.addAttribute("location", "대전");
        model.addAttribute("storeList", newstoreList);
        return "store/store_list";
    }


}
