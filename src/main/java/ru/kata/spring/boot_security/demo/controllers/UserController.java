package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.models.UserRole;
import ru.kata.spring.boot_security.demo.services.RoleServiceImpl;
import ru.kata.spring.boot_security.demo.services.UserRoleServiceImpl;
import ru.kata.spring.boot_security.demo.services.UserServiceImpl;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/user")
public class UserController {
    private final UserServiceImpl userService;
    private final RoleServiceImpl roleService;
    private final UserRoleServiceImpl userRoleService;

    @Autowired
    public UserController(UserServiceImpl userService, RoleServiceImpl roleService, UserRoleServiceImpl userRoleService) {
        this.userService = userService;
        this.roleService = roleService;
        this.userRoleService = userRoleService;
        prepareUsers();
        prepareRoles();
        prepareUserRoles();
    }

    //Подготовка заготовки базы - начало
    private void prepareUserRoles() {
        List<UserRole> userRoleList = UserRole.getRolesListDefault();
        for (UserRole userRole: userRoleList) {
            userRoleService.saveUserRole(userRole);
        }
    }

    private void prepareUsers() {
        List<User> userList = User.getUsersListDefault();
        for (User user: userList) {
            userService.saveUser(user, null);
        }
    }

    private void prepareRoles() {
        List<Role> roleList = Role.getRolesListDefault();
        for (Role role: roleList) {
            roleService.saveRole(role);
        }
    }
    //Подготовка заготовки базы - окончание

    @GetMapping()
    public String getUser(Principal principal, Model model) {
        model.addAttribute("user", userService.findByUsername(principal.getName()));
        return "user/user";
    }
}
