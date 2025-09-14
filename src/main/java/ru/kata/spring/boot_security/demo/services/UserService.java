package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.List;

public interface UserService extends UserDetailsService {

    User findByUsername(String username);

    User findByEmail(String email);

    List<User> findAllUsers();

    void saveUser(User user, String[] roles);

    User findByIdUsers(Long id);

    void updateUser(Long id, User user, String[] roles);

    void deleteByIdUsers(Long id);
}
