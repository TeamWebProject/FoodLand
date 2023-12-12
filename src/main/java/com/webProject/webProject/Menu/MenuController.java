package com.webProject.webProject.Menu;

import com.webProject.webProject.Photo.PhotoService;
import com.webProject.webProject.Store.Store;
import com.webProject.webProject.Store.StoreService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@RequestMapping("/menu")
@RequiredArgsConstructor
@Controller
public class MenuController {
    private final MenuService menuService;
    private final StoreService storeService;
    private final PhotoService photoService;
    @Value("${ImgLocation}")
    public String imgLocation;
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/addmenu")
    public String addmenu(Integer storeid) {
        Store store = storeService.findstoreById(storeid);
        menuService.setDefaultMenu(store);
        return "redirect:/store/menuList/"+ store.getId();
    }

    @PostMapping("/update")
    public String update(Integer menuid, String menuName, String pricestring, MultipartFile file) throws Exception {
        Menu menu = menuService.findMenu(menuid);
        if (menuName == null || menuName.isEmpty()) {
            menu.setMenuName("--MENU--");
        } else {
            menu.setMenuName(menuName);
        }

        if (pricestring == null || pricestring.isEmpty()) {
            menu.setPrice(0);
        } else {
            menu.setPrice(Integer.valueOf(pricestring));
        }
//        boolean filesSelected = fileList.stream().anyMatch(file -> !file.isEmpty());    // false -> true
//        if (!filesSelected) {   //false
//            photoService.savedefaultImgsForMenu(menu, fileList);
//        } else {
//            photoService.saveImgsForMenu(menu, fileList);
//        }
//        menuService.setMenu(menu);
//        return "redirect:/store/menuList/" + menu.getStore().getId();

        if (file != null && !file.isEmpty()) {
            // 파일이 선택된 경우에만 파일 저장 로직을 실행
            photoService.deleteMenuImage(menu);
            photoService.saveImgsForMenu(menu, Collections.singletonList(file));
        } else if (menu.getPhotoList().isEmpty()){
            // 파일이 선택되지 않았고, 저장된 이미지 없을 경우 기본 이미지 저장 로직 실행
            photoService.savedefaultImgsForMenu(menu, Collections.emptyList());
        }

        menuService.setMenu(menu);
        return "redirect:/store/menuList/" + menu.getStore().getId();

    }


    @PreAuthorize("isAuthenticated()")
    @PostMapping("/delete")
    public String delete(Integer menuid) {
        Menu menu = menuService.findMenu(menuid);
        menuService.deleteMenu(menu);
        return "redirect:/store/menuList/"+ menu.getStore().getId();
    }
}
