package com.webProject.webProject.User;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByuserId(String userId);

    List<User> findByRole(String role);

    @Query("SELECT DISTINCT u FROM User u WHERE u.role = :role AND u.nickname LIKE %:kw%")
    Page<User> findAllByRoleAndNicknameContaining(@Param("role") String role, @Param("kw") String kw, Pageable pageable);

    List<User> findByEmail(String email);

    List<User> findByPhone(String userPhone);

    User findByrole(String role);
}
