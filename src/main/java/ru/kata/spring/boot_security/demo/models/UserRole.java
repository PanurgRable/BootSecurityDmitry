package ru.kata.spring.boot_security.demo.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@NoArgsConstructor
@Getter
@Setter
@Table(name = "users_roles")
public class UserRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name="user_id")
    private Long userId;

    @Column(name="role_id")
    private Long roleId;

    public UserRole(Long userId, Long roleId) {
        this.userId = userId;
        this.roleId = roleId;
    }

    public static List<UserRole> getRolesListDefault() {
        List<UserRole> userRoleList = new ArrayList<>();
        userRoleList.add(new UserRole(1L, 1L));
        userRoleList.add(new UserRole(1L, 2L));
        userRoleList.add(new UserRole(2L, 2L));
        return userRoleList;
    }
}
