package com.webProject.webProject.Store;

import com.webProject.webProject.User.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface StoreRepository extends JpaRepository<Store, Integer> {

    @Query("select distinct s from Store s where s.jibunAddress like %:kw%")
    List<Store> findAllByKeyword(@Param("kw") String kw);


//    Page<Store> findAll(Pageable pageable);

    Page<Store> findAllById(Integer userid, Pageable pageable);


    @Query("SELECT DISTINCT s FROM Store s WHERE s.name LIKE %:kw%")
    Page<Store> findStoreByKeyword(@Param("kw") String kw, Pageable pageable);

}
