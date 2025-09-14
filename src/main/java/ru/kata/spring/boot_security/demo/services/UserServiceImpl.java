package ru.kata.spring.boot_security.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    private final RoleServiceImpl roleService;

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleServiceImpl roleService, @Lazy PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("Пользователь '%s' не найден", username));
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                roleService.mapRolesToAuthorities((List<Role>) user.getRoles()));
    }

    @Transactional
    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        User user = findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("Пользователь с почтой '%s' не найден", email));
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                roleService.mapRolesToAuthorities((List<Role>) user.getRoles()));
    }

    // READ
    /* Одного по логину */
    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /* Одного по id */
    @Override
    public User findByIdUsers(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("Пользователь не найден"));
    }

    /* Всех */
    @Override
    public List<User> findAllUsers() {
        return (List<User>) userRepository.findAll();
    }

    // CREATE
    @Override
    @Transactional
    public void saveUser(User user, String[] roles) {
        if (roles != null) {
            Set<Role> roleSet = new HashSet<>();
            for (String s: roles) {
                roleSet.add(roleService.findRoleByAuthority(s));
            }
            user.setRoles(roleSet);
        }
        encodeUserPassword(user);
        userRepository.save(user);
    }

    // UPDATE
    @Override
    @Transactional
    public void updateUser(Long id, User user, String[] roles) {
        User userDb = findByIdUsers(id);
        userDb.setFirstName(user.getFirstName());
        userDb.setLastName(user.getLastName());
        userDb.setEmail(user.getEmail());
        userDb.setUsername(user.getUsername());
        userDb.setPassword(user.getPassword());
        if (roles != null) {
            Set<Role> roleSet = new HashSet<>();
            for (String s: roles) {
                roleSet.add(roleService.findRoleByAuthority(s));
            }
            userDb.setRoles(roleSet);
        }
        encodeUserPassword(user);
        userRepository.save(userDb);
    }

    // DELETE
    @Override
    @Transactional
    public void deleteByIdUsers(Long id) {
        userRepository.deleteById(id);
    }

    // Technical
    private void encodeUserPassword(User user) {
        if (!user.getPassword().startsWith("$")) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
    }

}
