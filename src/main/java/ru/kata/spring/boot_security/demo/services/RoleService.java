package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.GrantedAuthority;
import ru.kata.spring.boot_security.demo.models.Role;

import java.util.List;

public interface RoleService {
    void saveRole(Role role);
    List<Role> findAllRoles();

    Role findRoleByAuthority(String authority);
    List<? extends GrantedAuthority> mapRolesToAuthorities(List<Role> roles);
}
